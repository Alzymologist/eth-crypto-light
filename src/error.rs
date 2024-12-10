use mnemonic_external::error::ErrorMnemonic;

#[derive(Debug)]
pub enum Error {
    BadTweak,
    HmacInvalidMixInLength,
    InvalidDerivationElement,
    InvalidEntropyEntry(ErrorMnemonic),
    InvalidPhraseEntry(ErrorMnemonic),
    NonZeroScalarFromBytes,
    Pbkdf2Internal,
    SignatureGen,
}
