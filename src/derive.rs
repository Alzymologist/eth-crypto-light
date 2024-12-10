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

use lazy_static::lazy_static;
use regex::Regex;

//use crate::error::Error;

lazy_static! {
    static ref REG_DERIVATION_SET: Regex =
        Regex::new(r"^(?P<derivation_set>/[0-9]+'?)*$").expect("checked value");
    static ref REG_SINGLE_DERIVATION: Regex =
        Regex::new(r"/(?P<derivation>[0-9]+'?)").expect("checked value");
}

/// Hardener border, half the highest `u32` value.
///
/// Both hardened and regular derivation elements must have corresponding `u32`
/// indices below `HALFWAY`.
pub const HALFWAY: u32 = 0x8000_0000;

/// Radix for parsing u32 index values.
pub const RADIX: u32 = 10;

#[derive(Debug)]
pub struct DerivationPath(pub Vec<DerivationElement>);

#[derive(Clone, Copy, Debug)]
pub enum DerivationElement {
    Hardened(u32),
    Regular(u32),
}

impl DerivationElement {
    pub fn inner(&self) -> u32 {
        match self {
            DerivationElement::Hardened(a) => *a,
            DerivationElement::Regular(a) => *a,
        }
    }
    pub fn is_valid(&self) -> bool {
        self.inner() < HALFWAY
    }
    pub fn display(&self) -> String {
        match self {
            DerivationElement::Hardened(a) => format!("{a}'"),
            DerivationElement::Regular(a) => a.to_string(),
        }
    }
}

impl DerivationPath {
    /// Generate `DerivationPath` from `str` entry, with checked elements.
    pub fn cut_derivation(path_entry: &str) -> Option<Self> {
        if REG_DERIVATION_SET.captures(path_entry).is_some() {
            let mut elements: Vec<DerivationElement> = Vec::new();
            for caps in REG_SINGLE_DERIVATION.captures_iter(path_entry) {
                if let Some(derivation) = caps.name("derivation") {
                    let derivation_str = derivation.as_str();
                    if derivation_str.ends_with('\'') {
                        if let Ok(index) =
                            u32::from_str_radix(derivation_str.trim_end_matches('\''), RADIX)
                        {
                            if index < HALFWAY {
                                elements.push(DerivationElement::Hardened(index))
                            } else {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    } else if let Ok(index) = u32::from_str_radix(derivation_str, RADIX) {
                        if index < HALFWAY {
                            elements.push(DerivationElement::Regular(index))
                        } else {
                            let index_reduced = index - HALFWAY;
                            elements.push(DerivationElement::Hardened(index_reduced))
                        }
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            Some(Self(elements))
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        self.0
            .iter()
            .fold(true, |acc, element| acc & element.is_valid())
    }

    pub fn display(&self) -> Option<String> {
        if self.is_valid() {
            let mut out = String::from("m");
            for element in self.0.iter() {
                out.push('/');
                out.push_str(&element.display())
            }
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(any(feature = "std", test))]
#[cfg(test)]
mod tests {

    use super::DerivationPath;

    const GOOD_PATHS: &[(&str, &str)] = &[
        ("/44'/60'/0'/0/1", "m/44'/60'/0'/0/1"),
        ("/1'/2", "m/1'/2"),
        ("", "m"),
        ("/2147483648/3", "m/0'/3"),
        ("/4294967295/4", "m/2147483647'/4"),
    ];

    const BAD_PATHS: &[&str] = &[
        "/4294967295'/2",
        "//3",
        "234/",
        "/34'2/23",
        "/9/",
        "67/7///88",
        "/0/'",
    ];

    #[test]
    fn good_paths() {
        for (path_entered, path_printed) in GOOD_PATHS {
            let derivation_path = DerivationPath::cut_derivation(path_entered).unwrap();
            assert_eq!(derivation_path.display().unwrap(), *path_printed);
        }
    }

    #[test]
    fn bad_paths() {
        for path in BAD_PATHS {
            assert!(DerivationPath::cut_derivation(path).is_none());
        }
    }
}
