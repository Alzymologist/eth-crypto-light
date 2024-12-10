#[cfg(any(feature = "std", test))]
use std::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use hmac::{Hmac, Mac};
use k256::{
    ecdsa::{RecoveryId, SigningKey, VerifyingKey},
    NonZeroScalar,
};
use mnemonic_external::{AsWordList, WordSet};
use sha2::Sha512;
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derive::{DerivationElement, DerivationPath, HALFWAY};
use crate::error::Error;
use crate::seed::seed;

pub const ADDRESS_20_LEN: usize = 20;
pub const FULL_PUBLIC_LEN: usize = 65;

pub const BYTES_32: usize = 32;

pub const START_FOR_ADDRESS_20: usize = 12;
pub const START_FOR_PUBLIC_HASHING: usize = 1;

pub const MIX_IN: &[u8; 12] = b"Bitcoin seed";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Address20(pub [u8; ADDRESS_20_LEN]);

/// Set of letters in hexadecimal representation of `Address20` hash that cause
/// the change of letter to uppercase.
pub const UPPERCASE_SET: &[char] = &['8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

impl Address20 {
    /// Hexadecimal representation of `Address20` according to
    /// [EIP-55](https://eips.ethereum.org/EIPS/eip-55)
    pub fn hex(&self) -> String {
        let hex = hex::encode(self.0);
        println!("hex: {hex}");

        let mut hash = [0u8; BYTES_32];
        let mut hasher = Keccak::v256();
        hasher.update(hex.as_bytes());
        hasher.finalize(&mut hash);

        let hex_hash_chars: Vec<char> = hex::encode(hash).chars().collect();

        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, mut ch) in hex.chars().enumerate() {
            if UPPERCASE_SET.contains(&hex_hash_chars[i]) {
                ch.make_ascii_uppercase()
            }
            out.push(ch)
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FullPublic(pub [u8; FULL_PUBLIC_LEN]);

impl FullPublic {
    pub fn address20(&self) -> Address20 {
        let mut digested_public_key = [0u8; BYTES_32];
        let mut hasher = Keccak::v256();
        hasher.update(&self.0[START_FOR_PUBLIC_HASHING..]);
        hasher.finalize(&mut digested_public_key);

        Address20(
            digested_public_key[START_FOR_ADDRESS_20..]
                .try_into()
                .expect("static length, always fits"),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Signature {
    pub r: [u8; BYTES_32],
    pub s: [u8; BYTES_32],
    pub v: u8,
}

impl Signature {
    pub fn is_correct_transaction(
        &self,
        rlp_encoded_transaction_bytes: &[u8],
        optional_transaction_type: Option<u8>,
        chain_id: u8,
        address20_known: &Address20,
    ) -> bool {
        let recid_byte = self.v - RECID_ADDITION_TRANSACTION - chain_id * 2;
        if let Some(recid) = RecoveryId::from_byte(recid_byte) {
            let mut signature_ecdsa_bytes: [u8; BYTES_32 * 2] = [0; BYTES_32 * 2];
            signature_ecdsa_bytes[0..BYTES_32].copy_from_slice(&self.r);
            signature_ecdsa_bytes[BYTES_32..BYTES_32 * 2].copy_from_slice(&self.s);
            if let Ok(signature_ecdsa) =
                k256::ecdsa::Signature::from_bytes(&(signature_ecdsa_bytes).into())
            {
                if let Ok(verifying_key) = VerifyingKey::recover_from_prehash(
                    &hash_transaction(rlp_encoded_transaction_bytes, optional_transaction_type),
                    &signature_ecdsa,
                    recid,
                ) {
                    let full_public = FullPublic(
                        verifying_key
                            .to_encoded_point(false)
                            .as_bytes()
                            .try_into()
                            .expect("static langth, always fits"),
                    );
                    let address20_found = full_public.address20();
                    &address20_found == address20_known
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn is_correct_message(&self, message_bytes: &[u8], address20_known: &Address20) -> bool {
        let recid_byte = self.v - RECID_ADDITION_MSG;
        if let Some(recid) = RecoveryId::from_byte(recid_byte) {
            let mut signature_ecdsa_bytes: [u8; BYTES_32 * 2] = [0; BYTES_32 * 2];
            signature_ecdsa_bytes[0..BYTES_32].copy_from_slice(&self.r);
            signature_ecdsa_bytes[BYTES_32..BYTES_32 * 2].copy_from_slice(&self.s);
            if let Ok(signature_ecdsa) =
                k256::ecdsa::Signature::from_bytes(&(signature_ecdsa_bytes).into())
            {
                if let Ok(verifying_key) = VerifyingKey::recover_from_prehash(
                    &hash_message(message_bytes),
                    &signature_ecdsa,
                    recid,
                ) {
                    let full_public = FullPublic(
                        verifying_key
                            .to_encoded_point(false)
                            .as_bytes()
                            .try_into()
                            .expect("static langth, always fits"),
                    );
                    let address20_found = full_public.address20();
                    &address20_found == address20_known
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Signer(SigningKey);

impl Signer {
    fn from_checked_phrase(
        phrase: &str,
        derivation_path: DerivationPath,
        password: &str,
    ) -> Result<Self, Error> {
        let mut seed_array = seed(phrase.as_bytes(), password)?;
        match nzs_and_chain_code(MIX_IN, &seed_array) {
            Ok((mut nzs, mut chain_code)) => {
                seed_array.zeroize();
                for derivation_element in derivation_path.0.iter() {
                    let (new_nzs, new_chain_code) =
                        derive_child(nzs, chain_code, derivation_element)?;
                    nzs = new_nzs;
                    chain_code = new_chain_code;
                }
                Ok(Signer(SigningKey::from(nzs)))
            }
            Err(e) => {
                seed_array.zeroize();
                Err(e)
            }
        }
    }

    pub fn from_entropy<L: AsWordList>(
        entropy: &[u8],
        derivation_path: DerivationPath,
        password: &str,
        wordlist: &L,
    ) -> Result<Self, Error> {
        let word_set = WordSet::from_entropy(entropy).map_err(Error::InvalidEntropyEntry)?;
        let phrase = word_set
            .to_phrase(wordlist)
            .map_err(Error::InvalidEntropyEntry)?;
        Self::from_checked_phrase(&phrase, derivation_path, password)
    }

    pub fn from_phrase<L: AsWordList>(
        phrase: &str,
        derivation_path: DerivationPath,
        password: &str,
        wordlist: &L,
    ) -> Result<Self, Error> {
        let mut word_set = WordSet::new();
        for word in phrase.split(' ') {
            word_set
                .add_word(word, wordlist)
                .map_err(Error::InvalidPhraseEntry)?;
        }
        let _entropy_calc = word_set.to_entropy().map_err(Error::InvalidPhraseEntry)?;
        Self::from_checked_phrase(phrase, derivation_path, password)
    }

    pub fn full_public(&self) -> FullPublic {
        FullPublic(
            self.0
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .expect("static langth, always fits"),
        )
    }

    pub fn public_address20(&self) -> Address20 {
        self.full_public().address20()
    }

    /// Signing message bytes
    ///
    /// See [EIP-191](https://eips.ethereum.org/EIPS/eip-191) (version 0x01).
    pub fn sign_message(&self, message_bytes: &[u8]) -> Result<Signature, Error> {
        let (signature_ecdsa, recid) = self
            .0
            .sign_prehash_recoverable(&hash_message(message_bytes))
            .map_err(|_| Error::SignatureGen)?;
        let (r_bytes, s_bytes) = signature_ecdsa.split_bytes();
        Ok(Signature {
            r: r_bytes.into(),
            s: s_bytes.into(),
            v: recid.to_byte() + RECID_ADDITION_MSG,
        })
    }

    /// Signing transaction
    pub fn sign_transaction(
        &self,
        rlp_encoded_transaction_bytes: &[u8],
        optional_transaction_type: Option<u8>,
        chain_id: u8,
    ) -> Result<Signature, Error> {
        let (signature_ecdsa, recid) = self
            .0
            .sign_prehash_recoverable(&hash_transaction(
                rlp_encoded_transaction_bytes,
                optional_transaction_type,
            ))
            .map_err(|_| Error::SignatureGen)?;
        let (r_bytes, s_bytes) = signature_ecdsa.split_bytes();
        Ok(Signature {
            r: r_bytes.into(),
            s: s_bytes.into(),
            v: recid.to_byte() + RECID_ADDITION_TRANSACTION + chain_id * 2,
        })
    }
}

pub const MESSAGE_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";
pub const RECID_ADDITION_MSG: u8 = 27;
pub const RECID_ADDITION_TRANSACTION: u8 = 35;

/// Hashing message bytes, after [EIP-191](https://eips.ethereum.org/EIPS/eip-191) (version 0x01).
///
/// Hashed bytes:
/// | b`\x19Ethereum Signed Message:\n` | message length, in bytes, printed to string, transformed to utf8 bytes | message itself |
///
/// Bytes are hashed with `keccak256` hasher.
pub fn hash_message(message_bytes: &[u8]) -> [u8; BYTES_32] {
    let mut hash = [0u8; BYTES_32];
    let mut hasher = Keccak::v256();
    hasher.update(MESSAGE_PREFIX);
    hasher.update(message_bytes.len().to_string().as_bytes());
    hasher.update(message_bytes);
    hasher.finalize(&mut hash);
    hash
}

pub fn hash_transaction(
    rlp_encoded_transaction_bytes: &[u8],
    optional_transaction_type: Option<u8>,
) -> [u8; BYTES_32] {
    let mut hash = [0u8; BYTES_32];
    let mut hasher = Keccak::v256();
    if let Some(transaction_byte) = optional_transaction_type {
        hasher.update(&[transaction_byte]);
    }
    hasher.update(rlp_encoded_transaction_bytes);
    hasher.finalize(&mut hash);
    hash
}

#[derive(ZeroizeOnDrop)]
struct ChainCode([u8; BYTES_32]);

fn nzs_and_chain_code(mix_in: &[u8], bytes: &[u8]) -> Result<(NonZeroScalar, ChainCode), Error> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(mix_in).map_err(|_| Error::HmacInvalidMixInLength)?;
    mac.update(bytes);
    let finalized_mac = mac.finalize().into_bytes();

    let nzs = NonZeroScalar::try_from(&finalized_mac[..BYTES_32])
        .map_err(|_| Error::NonZeroScalarFromBytes)?;
    let chain_code = ChainCode(
        finalized_mac[BYTES_32..]
            .try_into()
            .expect("static length, always fits"),
    );

    Ok((nzs, chain_code))
}

const DERIVATION_DATA_CAP: usize = 37;

fn derive_child(
    parent_nzs: NonZeroScalar,
    parent_chain_code: ChainCode,
    derivation_element: &DerivationElement,
) -> Result<(NonZeroScalar, ChainCode), Error> {
    if derivation_element.is_valid() {
        let parent_key = SigningKey::from(parent_nzs);
        let mut data = Vec::with_capacity(DERIVATION_DATA_CAP);
        match derivation_element {
            DerivationElement::Hardened(index) => {
                data.push(0);

                // signing key length is static 32 bytes
                data.extend_from_slice(&parent_key.to_bytes());

                // u32 index length is static 4 bytes
                data.extend(&(index + HALFWAY).to_be_bytes());
            }
            DerivationElement::Regular(index) => {
                // verifying key len in sec1 bytes representation is static 33 bytes
                data.extend_from_slice(&parent_key.verifying_key().to_sec1_bytes());

                // u32 index length is static 4 bytes
                data.extend_from_slice(&index.to_be_bytes());
            }
        }
        match nzs_and_chain_code(&parent_chain_code.0, &data) {
            Ok((tweak_nzs, chain_code)) => {
                data.zeroize();
                let tweaked_scalar = tweak_nzs.add(&parent_nzs);
                let tweaked: NonZeroScalar =
                    Option::from(NonZeroScalar::new(tweaked_scalar)).ok_or(Error::BadTweak)?;
                Ok((tweaked, chain_code))
            }
            Err(e) => {
                data.zeroize();
                Err(e)
            }
        }
    } else {
        Err(Error::InvalidDerivationElement)
    }
}

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use mnemonic_external::regular::InternalWordList;

    use super::{Address20, DerivationPath, FullPublic, Signature, Signer};

    // Data examples from <https://docs.ethers.org/v5/api/signer/>
    const KNOWN_PHRASE: &str =
        "announce room limb pattern dry unit scale effort smooth jazz weasel alcohol";
    const KNOWN_DERIVATION: &str = "/44'/60'/0'/0/0";

    const KNOWN_PUBLIC_KEY_HEX: &str = "0x04b9e72dfd423bcf95b3801ac93f4392be5ff22143f9980eb78b3a860c4843bfd04829ae61cdba4b3b1978ac5fc64f5cc2f4350e35a108a9c9a92a81200a60cd64";
    const KNOWN_ADDRESS20_HEX: &str = "0x71CB05EE1b1F506fF321Da3dac38f25c0c9ce6E1";

    const KNOWN_MESSAGE: &str = "Hello World";
    const KNOWN_MESSAGE_SIGNATURE_HEX: &str = "0x14280e5885a19f60e536de50097e96e3738c7acae4e9e62d67272d794b8127d31c03d9cd59781d4ee31fb4e1b893bd9b020ec67dfa65cfb51e2bdadbb1de26d91c";

    // Transaction example from <https://docs.ethers.org/v5/api/signer/>
    //
    // ```
    // tx = {
    //   to: "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
    //   value: utils.parseEther("1.0")
    // }
    // ```
    //
    // Signed transaction blob:
    //
    // '0xf865808080948ba1f109551bd432803012645ac136ddd64dba72880de0b6b3a76400008026a0918e294306d177ab7bd664f5e141436563854ebe0a3e523b9690b4922bbb52b8a01181612cec9c431c4257a79b8c9f0c980a2c49bb5a0e6ac52949163eeb565dfc'
    //
    // This is rlp encoded transaction with signature parts, when decoded gives:
    //
    // ```
    // let mock_struct = MockStruct {
    //     nonce: 0,
    //     gasprice: 0,
    //     startgas: 0,
    //     address20_to: hex::decode("8ba1f109551bd432803012645ac136ddd64dba72").unwrap().try_into().unwrap(),
    //     value: 1000000000000000000,
    //     data_string: String::new(),
    //     v: 38,
    //     r: hex::decode("918e294306d177ab7bd664f5e141436563854ebe0a3e523b9690b4922bbb52b8").unwrap().try_into().unwrap(),
    //     s: hex::decode("1181612cec9c431c4257a79b8c9f0c980a2c49bb5a0e6ac52949163eeb565dfc").unwrap().try_into().unwrap(),
    // };
    // ```
    //
    // Hash for signing is formed using rlp encoded transaction.
    //
    // ```
    // let mock_struct_to_hash = MockStructToHash {
    //     nonce: 0,
    //     gasprice: 0,
    //     startgas: 0,
    //     address20_to: hex::decode("8ba1f109551bd432803012645ac136ddd64dba72").unwrap().try_into().unwrap(),
    //     value: 1000000000000000000,
    //     data_string: String::new(),
    // };
    // ```
    //
    // These recalculations were done elsewhere.
    //
    // Encoded blob to be signed is `KNOWN_TRANSACTION_BYTES_HEX`.
    const KNOWN_TRANSACTION_BYTES_HEX: &str =
        "e2808080948ba1f109551bd432803012645ac136ddd64dba72880de0b6b3a764000080";
    const KNOWN_TRANSACTION_TYPE: Option<u8> = None;
    const KNOWN_CHAIN_ID: u8 = 1;
    const KNOWN_TRANSACTION_SIGNATURE_HEX_R: &str =
        "0x918e294306d177ab7bd664f5e141436563854ebe0a3e523b9690b4922bbb52b8";
    const KNOWN_TRANSACTION_SIGNATURE_HEX_S: &str =
        "0x1181612cec9c431c4257a79b8c9f0c980a2c49bb5a0e6ac52949163eeb565dfc";
    const KNOWN_TRANSACTION_SIGNATURE_HEX_V: u8 = 0x26;

    #[test]
    fn public_to_address20() {
        let full_public = FullPublic(
            hex::decode(KNOWN_PUBLIC_KEY_HEX.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let calculated_address20 = full_public.address20();

        let known_address20 = Address20(
            hex::decode(KNOWN_ADDRESS20_HEX.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert_eq!(calculated_address20, known_address20);
        assert_eq!(KNOWN_ADDRESS20_HEX, calculated_address20.hex());
    }

    #[test]
    fn phrase_to_signer() {
        let derivation_path = DerivationPath::cut_derivation(KNOWN_DERIVATION).unwrap();
        let internal_word_list = InternalWordList;
        let signer =
            Signer::from_phrase(KNOWN_PHRASE, derivation_path, "", &internal_word_list).unwrap();
        let calculated_public = signer.full_public();

        let known_public = FullPublic(
            hex::decode(KNOWN_PUBLIC_KEY_HEX.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert_eq!(calculated_public, known_public);
    }

    #[test]
    fn signing_message() {
        let derivation_path = DerivationPath::cut_derivation(KNOWN_DERIVATION).unwrap();
        let internal_word_list = InternalWordList;
        let signer =
            Signer::from_phrase(KNOWN_PHRASE, derivation_path, "", &internal_word_list).unwrap();
        let calculated_signature = signer.sign_message(KNOWN_MESSAGE.as_bytes()).unwrap();

        let known_signature_bytes =
            hex::decode(KNOWN_MESSAGE_SIGNATURE_HEX.trim_start_matches("0x")).unwrap();
        let known_signature = Signature {
            r: known_signature_bytes[..32].try_into().unwrap(),
            s: known_signature_bytes[32..64].try_into().unwrap(),
            v: known_signature_bytes[64],
        };

        assert_eq!(calculated_signature, known_signature);
    }

    #[test]
    fn signing_transaction() {
        let derivation_path = DerivationPath::cut_derivation(KNOWN_DERIVATION).unwrap();
        let internal_word_list = InternalWordList;
        let signer =
            Signer::from_phrase(KNOWN_PHRASE, derivation_path, "", &internal_word_list).unwrap();
        let transaction_bytes =
            hex::decode(KNOWN_TRANSACTION_BYTES_HEX.trim_start_matches("0x")).unwrap();
        let calculated_signature = signer
            .sign_transaction(&transaction_bytes, KNOWN_TRANSACTION_TYPE, KNOWN_CHAIN_ID)
            .unwrap();

        let known_signature = Signature {
            r: hex::decode(KNOWN_TRANSACTION_SIGNATURE_HEX_R.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            s: hex::decode(KNOWN_TRANSACTION_SIGNATURE_HEX_S.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            v: KNOWN_TRANSACTION_SIGNATURE_HEX_V,
        };

        assert_eq!(calculated_signature, known_signature);
    }

    #[test]
    fn verify_signature_transaction() {
        let known_signature = Signature {
            r: hex::decode(KNOWN_TRANSACTION_SIGNATURE_HEX_R.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            s: hex::decode(KNOWN_TRANSACTION_SIGNATURE_HEX_S.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            v: KNOWN_TRANSACTION_SIGNATURE_HEX_V,
        };

        let transaction_bytes =
            hex::decode(KNOWN_TRANSACTION_BYTES_HEX.trim_start_matches("0x")).unwrap();

        let known_address20 = Address20(
            hex::decode(KNOWN_ADDRESS20_HEX.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert!(known_signature.is_correct_transaction(
            &transaction_bytes,
            KNOWN_TRANSACTION_TYPE,
            KNOWN_CHAIN_ID,
            &known_address20
        ));
    }

    #[test]
    fn verify_signature_message() {
        let known_signature_bytes =
            hex::decode(KNOWN_MESSAGE_SIGNATURE_HEX.trim_start_matches("0x")).unwrap();
        let known_signature = Signature {
            r: known_signature_bytes[..32].try_into().unwrap(),
            s: known_signature_bytes[32..64].try_into().unwrap(),
            v: known_signature_bytes[64],
        };

        let known_address20 = Address20(
            hex::decode(KNOWN_ADDRESS20_HEX.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert!(known_signature.is_correct_message(KNOWN_MESSAGE.as_bytes(), &known_address20));
    }
}
