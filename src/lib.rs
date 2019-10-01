// Copyright 2016 Andrew Baumhauer <andy@baumhauer.us>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Represent and parse IEEE EUI-64 Media Access Control addresses
//! The IEEE claims trademarks on the names EUI-64 and EUI-64, in which EUI is an
//! abbreviation for Extended Unique Identifier.

#![doc(
    html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
    html_favicon_url = "https://www.rust-lang.org/favicon.ico",
    html_root_url = "https://doc.rust-lang.org/eui64/"
)]
#![cfg_attr(test, deny(warnings))]

#[cfg(feature = "serde")]
extern crate serde;
#[cfg(feature = "serde_json")]
extern crate serde_json;
#[cfg(feature = "with_postgres")]
#[macro_use]
extern crate tokio_postgres;

use std::default::Default;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "with_postgres")]
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A 64-bit (8 byte) buffer containing the EUI address
pub const EUI64LEN: usize = 8;
pub type Eui64 = [u8; EUI64LEN];

/// A MAC address (EUI-64)
#[repr(C)]
#[derive(Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct MacAddress8 {
    /// The 64-bit number stored in 8 bytes
    eui: Eui64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// Format to display MacAddress8
pub enum MacAddress8Format {
    /// Use - notaion
    Canonical,
    /// Use : notation
    HexString,
    /// Use . notation
    DotNotation,
    /// Use 0x notation
    Hexadecimal,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Ord, PartialOrd, Hash)]
/// Parsing errors
pub enum ParseError {
    /// Length is incorrect (should be 14 or 17)
    InvalidLength(usize),
    /// Character not [0-9a-fA-F]|'x'|'-'|':'|'.'
    InvalidCharacter(char, usize),
}

impl MacAddress8 {
    /// Create a new MacAddress8 from `[u8; 8]`.
    pub fn new(eui: Eui64) -> MacAddress8 {
        MacAddress8 { eui: eui }
    }

    /// Create a new MacAddress8 from a byte slice.
    ///
    /// Returns an error (without any description) if the slice doesn't have the proper length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() != EUI64LEN {
            return Err(());
        }
        let mut input: [u8; EUI64LEN] = Default::default();
        for i in 0..EUI64LEN {
            input[i] = bytes[i];
        }
        Ok(Self::new(input))
    }

    /// Returns empty EUI-64 address
    pub fn nil() -> MacAddress8 {
        MacAddress8 { eui: [0; EUI64LEN] }
    }

    /// Returns 'ff:ff:ff:ff:ff:ff', a MAC broadcast address
    pub fn broadcast() -> MacAddress8 {
        MacAddress8 {
            eui: [0xFF; EUI64LEN],
        }
    }

    /// Returns true if the address is '00:00:00:00:00:00'
    pub fn is_nil(&self) -> bool {
        self.eui.iter().all(|&b| b == 0)
    }

    /// Returns true if the address is 'ff:ff:ff:ff:ff:ff'
    pub fn is_broadcast(&self) -> bool {
        self.eui.iter().all(|&b| b == 0xFF)
    }

    /// Returns true if bit 1 of Y is 0 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_unicast(&self) -> bool {
        self.eui[0] & 1 == 0
    }

    /// Returns true if bit 1 of Y is 1 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_multicast(&self) -> bool {
        self.eui[0] & 1 == 1
    }

    /// Returns true if bit 2 of Y is 0 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_universal(&self) -> bool {
        self.eui[0] & 1 << 1 == 0
    }

    /// Returns true if bit 2 of Y is 1 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_local(&self) -> bool {
        self.eui[0] & 1 << 1 == 2
    }

    /// Returns a String representation in the format '00-00-00-00-00-00-00-00'
    pub fn to_canonical(&self) -> String {
        format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.eui[0], self.eui[1], self.eui[2], self.eui[3], self.eui[4], self.eui[5], self.eui[6], self.eui[7]
        )
    }

    /// Returns a String representation in the format '00:00:00:00:00:00:00:00'
    pub fn to_hex_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.eui[0], self.eui[1], self.eui[2], self.eui[3], self.eui[4], self.eui[5], self.eui[6], self.eui[7]
        )
    }

    /// Returns a String representation in the format '0000.0000.0000.0000'
    pub fn to_dot_string(&self) -> String {
        format!(
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            self.eui[0], self.eui[1], self.eui[2], self.eui[3], self.eui[4], self.eui[5], self.eui[6], self.eui[7]
        )
    }

    /// Returns a String representation in the format '0x0000000000000000'
    pub fn to_hexadecimal(&self) -> String {
        format!(
            "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.eui[0], self.eui[1], self.eui[2], self.eui[3], self.eui[4], self.eui[5], self.eui[6], self.eui[7]
        )
    }

    /// Returns a String representation in the EUI-64 interface ID format '0000:00ff:fe00:0000'
    pub fn to_interfaceid(&self) -> String {
        format!(
            "{:02x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}",
            (self.eui[0] ^ 0x02),
            self.eui[1],
            self.eui[2],
            self.eui[3],
            self.eui[4],
            self.eui[5]
        )
    }

    /// Returns a String representation in the IPv6 link local format 'ff80::0000:00ff:fe00:0000'
    pub fn to_link_local(&self) -> String {
        format!(
            "ff80::{:02x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}",
            (self.eui[0] ^ 0x02),
            self.eui[1],
            self.eui[2],
            self.eui[3],
            self.eui[4],
            self.eui[5]
        )
    }

    /// Returns a String in the format selected by fmt
    pub fn to_string(&self, fmt: MacAddress8Format) -> String {
        match fmt {
            MacAddress8Format::Canonical => self.to_canonical(),
            MacAddress8Format::HexString => self.to_hex_string(),
            MacAddress8Format::DotNotation => self.to_dot_string(),
            MacAddress8Format::Hexadecimal => self.to_hexadecimal(),
        }
    }

    /// Parses a String representation from any format supported
    pub fn parse_str(s: &str) -> Result<MacAddress8, ParseError> {
        let mut offset = 0; // Offset into the u8 Eui64 vector
        let mut hn: bool = false; // Have we seen the high nibble yet?
        let mut eui: Eui64 = [0; EUI64LEN];

        match s.len() {
            18 | 19 | 23 => {} // The formats are all 16 characters with 2(hex), 3(dot) or 7(:-.) delims
            _ => return Err(ParseError::InvalidLength(s.len())),
        }

        for (idx, c) in s.chars().enumerate() {
            if offset >= EUI64LEN {
                // We shouln't still be parsing
                return Err(ParseError::InvalidLength(s.len()));
            }

            match c {
                '0'..='9' | 'a'..='f' | 'A'..='F' => {
                    match hn {
                        false => {
                            // We will match '0' and run this even if the format is 0x
                            hn = true; // Parsed the high nibble
                            eui[offset] = (c.to_digit(16).unwrap() as u8) << 4;
                        }
                        true => {
                            hn = false; // Parsed the low nibble
                            eui[offset] += c.to_digit(16).unwrap() as u8;
                            offset += 1;
                        }
                    }
                }
                '-' | ':' | '.' => {}
                'x' | 'X' => {
                    match idx {
                        1 => {
                            // If idx = 1, we are possibly parsing 0x1234567890ab format
                            // Reset the offset to zero to ignore the first two characters
                            offset = 0;
                            hn = false;
                        }
                        _ => return Err(ParseError::InvalidCharacter(c, idx)),
                    }
                }
                _ => return Err(ParseError::InvalidCharacter(c, idx)),
            }
        }

        if offset == EUI64LEN {
            // A correctly parsed value is exactly 8 u8s
            Ok(MacAddress8::new(eui))
        } else {
            Err(ParseError::InvalidLength(s.len())) // Something slipped through
        }
    }

    /// Return the internal structure as a slice of bytes
    pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
        &self.eui
    }

    /// Returns an array in Eui64. Works as an inverse function of new()
    pub fn to_array(&self) -> Eui64 {
        self.eui
    }

    /// Returns Display MacAddress8Format, determined at compile time.
    pub fn get_display_format() -> MacAddress8Format {
        if cfg!(feature = "disp_hexstring") {
            MacAddress8Format::HexString
        } else {
            MacAddress8Format::Canonical
        }
    }
}

impl FromStr for MacAddress8 {
    type Err = ParseError;
    /// Create a MacAddress8 from String
    fn from_str(us: &str) -> Result<MacAddress8, ParseError> {
        MacAddress8::parse_str(us)
    }
}

impl Default for MacAddress8 {
    /// Create a Default MacAddress8 (00-00-00-00-00-00-00-00)
    fn default() -> MacAddress8 {
        MacAddress8::nil()
    }
}

impl fmt::Debug for MacAddress8 {
    /// Debug format for MacAddress8 is HexString notation
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MacAddress8(\"{}\")",
            self.to_string(MacAddress8Format::HexString)
        )
    }
}

impl fmt::Display for MacAddress8 {
    /// Display format is canonical format (00-00-00-00-00-00)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp_fmt = MacAddress8::get_display_format();
        write!(f, "{}", self.to_string(disp_fmt))
    }
}

impl fmt::Display for ParseError {
    /// Human readable error strings for ParseError enum
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::InvalidLength(found) => write!(
                f,
                "Invalid length; expecting 14 or 17 chars, found {}",
                found
            ),
            ParseError::InvalidCharacter(found, pos) => {
                write!(f, "Invalid character; found `{}` at offset {}", found, pos)
            }
        }
    }
}

impl Error for ParseError {
    /// Human readable description for ParseError enum
    fn description(&self) -> &str {
        "MacAddress8 parse error"
    }
}

#[cfg(feature = "serde")]
impl Serialize for MacAddress8 {
    /// Serialize a MacAddress8 as canonical form using the serde crate
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MacAddress8 {
    /// Deserialize a MacAddress8 from canonical form using the serde crate
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MacAddress8Visitor;
        impl<'de> de::Visitor<'de> for MacAddress8Visitor {
            type Value = MacAddress8;

            fn visit_str<E: de::Error>(self, value: &str) -> Result<MacAddress8, E> {
                value.parse().map_err(|err| E::custom(&format!("{}", err)))
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<MacAddress8, E> {
                MacAddress8::from_bytes(value).map_err(|_| E::invalid_length(value.len(), &self))
            }

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "either a string representation of a MAC address or 6-element byte array"
                )
            }
        }
        deserializer.deserialize_str(MacAddress8Visitor)
    }
}

#[cfg(feature = "with_postgres")]
impl<'a> FromSql<'a> for MacAddress8 {
    fn from_sql(_: &Type, raw: &[u8]) -> Result<MacAddress8, Box<dyn Error + Sync + Send>> {
        if raw.len() != 8 {
            return Err("invalid message length".into());
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(raw);
        Ok(MacAddress8::new(bytes))
    }

    accepts!(MACADDR8);
}

#[cfg(feature = "with_postgres")]
impl ToSql for MacAddress8 {
    fn to_sql(&self, _: &Type, w: &mut Vec<u8>) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        w.extend_from_slice(self.as_bytes());
        Ok(IsNull::No)
    }

    accepts!(MACADDR8);
    to_sql_checked!();
}

// ************** TESTS BEGIN HERE ***************
#[cfg(test)]
mod tests {
    use super::{Eui64, MacAddress8, MacAddress8Format, ParseError};

    #[test]
    fn test_new() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xAA, 0xBA];
        let mac = MacAddress8::new(eui);

        assert!(mac.eui[0..5] == eui[0..5]);
    }

    #[test]
    fn test_from_bytes() {
        assert_eq!(
            "12:34:56:ab:cd:ef:aa:bb",
            MacAddress8::from_bytes(&[0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xAA, 0xBB])
                .unwrap()
                .to_hex_string()
        );
        assert!(MacAddress8::from_bytes(&[0x12, 0x34, 0x56, 0xAB, 0xCD, 0xAA, 0xBB]).is_err());
    }

    #[test]
    fn test_nil() {
        let nil = MacAddress8::nil();
        let not_nil = MacAddress8::broadcast();
        assert_eq!("00:00:00:00:00:00:00:00", nil.to_hex_string());
        assert!(nil.is_nil());
        assert!(!not_nil.is_nil());
    }

    #[test]
    fn test_default() {
        let default = MacAddress8::default();
        assert!(default.is_nil());
    }

    #[test]
    fn test_broadcast() {
        let broadcast = MacAddress8::broadcast();
        let not_broadcast = MacAddress8::nil();
        assert_eq!("ff:ff:ff:ff:ff:ff:ff:ff", broadcast.to_hex_string());
        assert!(broadcast.is_broadcast());
        assert!(!not_broadcast.is_broadcast());
    }

    #[test]
    fn test_is_nil() {
        let nil = MacAddress8::nil();
        let not_nil = MacAddress8::parse_str("01:00:5E:AB:CD:EF:DE:AD").unwrap();
        assert!(nil.is_nil());
        assert!(!not_nil.is_nil());
    }

    #[test]
    fn test_is_broadcast() {
        let broadcast = MacAddress8::broadcast();
        let not_broadcast = MacAddress8::parse_str("01:00:5E:AB:CD:EF:DE:AD").unwrap();
        assert!(broadcast.is_broadcast());
        assert!(!not_broadcast.is_broadcast());
    }

    #[test]
    fn test_is_unicast() {
        let mac_u = MacAddress8::parse_str("FE:00:5E:AB:CD:EF:DE:AD").unwrap();
        let mac_m = MacAddress8::parse_str("01:00:5E:AB:CD:EF:DE:AD").unwrap();
        assert!(mac_u.is_unicast());
        assert!(!mac_m.is_unicast());
        assert_eq!("fe:00:5e:ab:cd:ef:de:ad", mac_u.to_hex_string()); // Catch modifying first octet
        let mac = MacAddress8::parse_str("FF:00:5E:AB:CD:EF:DE:AD").unwrap();
        assert!(!mac.is_unicast());
        assert_eq!("ff:00:5e:ab:cd:ef:de:ad", mac.to_hex_string()); // Catch modifying first octet
        assert!(MacAddress8::nil().is_unicast());
        assert!(!MacAddress8::broadcast().is_unicast());
    }

    #[test]
    fn test_is_multicast() {
        let mac_u = MacAddress8::parse_str("FE:00:5E:AB:CD:EF:BE:EF").unwrap();
        let mac_m = MacAddress8::parse_str("01:00:5E:AB:CD:EF:BE:EF").unwrap();
        assert!(!mac_u.is_multicast());
        assert!(mac_m.is_multicast());
        assert!(!MacAddress8::nil().is_multicast());
        assert_eq!("01:00:5e:ab:cd:ef:be:ef", mac_m.to_hex_string()); // Catch modifying first octet
        let mac = MacAddress8::parse_str("F0:00:5E:AB:CD:EF:BE:EF").unwrap();
        assert!(!mac.is_multicast());
        assert_eq!("f0:00:5e:ab:cd:ef:be:ef", mac.to_hex_string()); // Catch modifying first octet
        assert!(MacAddress8::broadcast().is_multicast());
    }

    #[test]
    fn test_is_universal() {
        let universal = MacAddress8::parse_str("11:24:56:AB:CD:EF:BE:EF").unwrap();
        let not_universal = MacAddress8::parse_str("12:24:56:AB:CD:EF:BE:EF").unwrap();
        assert!(universal.is_universal());
        assert!(!not_universal.is_universal());
        assert_eq!("11:24:56:ab:cd:ef:be:ef", universal.to_hex_string()); // Catch modifying first octet
    }

    #[test]
    fn test_is_local() {
        let local = MacAddress8::parse_str("06:34:56:AB:CD:EF:BE:EF").unwrap();
        let not_local = MacAddress8::parse_str("00:34:56:AB:CD:EF:BE:EF").unwrap();
        assert!(local.is_local());
        assert!(!not_local.is_local());
        assert_eq!("06:34:56:ab:cd:ef:be:ef", local.to_hex_string()); // Catch modifying first octet
    }

    #[test]
    fn test_to_canonical() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("12-34-56-ab-cd-ef-be-ef", mac.to_canonical());
    }

    #[test]
    fn test_to_hex_string() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("12:34:56:ab:cd:ef:be:ef", mac.to_hex_string());
    }

    #[test]
    fn test_to_dot_string() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("1234.56ab.cdef.beef", mac.to_dot_string());
    }

    #[test]
    fn test_to_hexadecimal() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("0x123456abcdefbeef", mac.to_hexadecimal());
    }

    /*#[test]
    fn test_to_interfaceid() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("1034:56ff:feab:cdef:beef", mac.to_interfaceid());
    }

    #[test]
    fn test_to_link_local() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!("ff80::1034:56ff:feab:cdef:beef", mac.to_link_local());
    }*/

    #[test]
    fn test_to_string() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!(
            "0x123456abcdefbeef",
            mac.to_string(MacAddress8Format::Hexadecimal)
        );
        assert_eq!(
            "1234.56ab.cdef.beef",
            mac.to_string(MacAddress8Format::DotNotation)
        );
        assert_eq!(
            "12:34:56:ab:cd:ef:be:ef",
            mac.to_string(MacAddress8Format::HexString)
        );
        assert_eq!(
            "12-34-56-ab-cd-ef-be-ef",
            mac.to_string(MacAddress8Format::Canonical)
        );
    }

    #[test]
    fn test_parse_str() {
        use super::ParseError::*;

        assert_eq!(
            "0x123456abcdefbeef",
            MacAddress8::parse_str("0x123456ABCDEFBEEF")
                .unwrap()
                .to_hexadecimal()
        );
        assert_eq!(
            "1234.56ab.cdef.beef",
            MacAddress8::parse_str("1234.56AB.CDEF.BEEF")
                .unwrap()
                .to_dot_string()
        );
        assert_eq!(
            "12:34:56:ab:cd:ef:be:ef",
            MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF")
                .unwrap()
                .to_hex_string()
        );
        assert_eq!(
            "12-34-56-ab-cd-ef-be-ef",
            MacAddress8::parse_str("12-34-56-AB-CD-EF-BE-EF")
                .unwrap()
                .to_canonical()
        );
        // Test error parsing
        assert_eq!(MacAddress8::parse_str(""), Err(InvalidLength(0)));
        assert_eq!(MacAddress8::parse_str("0"), Err(InvalidLength(1)));
        assert_eq!(
            MacAddress8::parse_str("123456ABCDEF"),
            Err(InvalidLength(12))
        );
        assert_eq!(
            MacAddress8::parse_str("1234567890ABCD"),
            Err(InvalidLength(14))
        );
        assert_eq!(
            MacAddress8::parse_str("1234567890ABCDEF"),
            Err(InvalidLength(16))
        );
        assert_eq!(
            MacAddress8::parse_str("01234567890ABCDEF"),
            Err(InvalidLength(17))
        );
        assert_eq!(
            MacAddress8::parse_str("0x1234567890A"),
            Err(InvalidLength(13))
        );
        assert_eq!(
            MacAddress8::parse_str("0x1234567890ABCDE"),
            Err(InvalidLength(17))
        );
        assert_eq!(
            MacAddress8::parse_str("0x00:00:00:00:"),
            Err(InvalidLength(14))
        );
        assert_eq!(
            MacAddress8::parse_str("0x00:00:00:00:00:"),
            Err(InvalidLength(17))
        );
        assert_eq!(
            MacAddress8::parse_str("::::::::::::::"),
            Err(InvalidLength(14))
        );
        assert_eq!(
            MacAddress8::parse_str(":::::::::::::::::"),
            Err(InvalidLength(17))
        );
        assert_eq!(
            MacAddress8::parse_str("0x0x0x0x0x0x0x0x0x"),
            Err(InvalidCharacter('x', 3))
        );
        assert_eq!(
            MacAddress8::parse_str("!0x000000000000000"),
            Err(InvalidCharacter('!', 0))
        );
        assert_eq!(
            MacAddress8::parse_str("0x000000000000000!"),
            Err(InvalidCharacter('!', 17))
        );
    }

    #[test]
    fn test_as_bytes() {
        let mac = MacAddress8::broadcast();
        let bytes = mac.as_bytes();

        assert!(bytes.len() == 8);
        assert!(bytes.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_compare() {
        let m1 = MacAddress8::nil();
        let m2 = MacAddress8::broadcast();
        assert!(m1 == m1);
        assert!(m2 == m2);
        assert!(m1 != m2);
        assert!(m2 != m1);
    }

    #[test]
    fn test_clone() {
        let m1 = MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF").unwrap();
        let m2 = m1.clone();
        assert!(m1 == m1);
        assert!(m2 == m2);
        assert!(m1 == m2);
        assert!(m2 == m1);
    }

    #[test]
    fn test_fmt_debug() {
        let mac = MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF").unwrap();
        assert_eq!(
            "MacAddress8(\"12:34:56:ab:cd:ef:be:ef\")".to_owned(),
            format!("{:?}", mac)
        );
    }

    #[test]
    fn test_fmt() {
        let mac = MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF").unwrap();
        match MacAddress8::get_display_format() {
            MacAddress8Format::HexString => {
                assert_eq!("12:34:56:ab:cd:ef:be:ef".to_owned(), format!("{}", mac))
            }
            _ => assert_eq!("12-34-56-ab-cd-ef-be-ef".to_owned(), format!("{}", mac)),
        };
    }

    #[test]
    fn test_fmt_parse_errors() {
        assert_eq!(
            "Err(InvalidLength(12))".to_owned(),
            format!("{:?}", MacAddress8::parse_str("123456ABCDEF"))
        );
        assert_eq!(
            "Err(InvalidCharacter(\'#\', 2))".to_owned(),
            format!("{:?}", MacAddress8::parse_str("12#34#56#AB#CD#EF#BE#EF"))
        );
    }

    #[test]
    #[cfg(feature = "serde_json")]
    fn test_serde_json_serialize() {
        use serde_json;
        let serialized =
            serde_json::to_string(&MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF").unwrap()).unwrap();
        assert_eq!("\"12-34-56-ab-cd-ef-be-ef\"", serialized);
    }

    #[test]
    #[cfg(feature = "serde_json")]
    fn test_serde_json_deserialize() {
        use serde_json;
        let mac = MacAddress8::parse_str("12:34:56:AB:CD:EF:BE:EF").unwrap();
        let deserialized: MacAddress8 = serde_json::from_str("\"12-34-56-AB-CD-EF-BE-EF\"").unwrap();
        assert_eq!(deserialized, mac);
    }

    #[test]
    fn test_macaddressformat_derive() {
        assert_eq!(MacAddress8Format::HexString, MacAddress8Format::HexString);
        assert_ne!(MacAddress8Format::HexString, MacAddress8Format::Canonical);
    }

    #[test]
    fn test_parseerror_fmt() {
        use std::error::Error;
        assert_eq!(
            "Invalid length; expecting 14 or 17 chars, found 2".to_owned(),
            format!("{}", ParseError::InvalidLength(2))
        );
        assert_eq!(
            "Invalid character; found `@` at offset 2".to_owned(),
            format!("{}", ParseError::InvalidCharacter('@', 2))
        );
        assert_eq!(
            "MacAddress8 parse error".to_owned(),
            format!("{}", ParseError::InvalidLength(2).description())
        );
    }

    #[test]
    fn test_to_array() {
        let eui: Eui64 = [0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF, 0xBE, 0xEF];
        let mac = MacAddress8::new(eui);
        assert_eq!(eui, MacAddress8::new(eui).to_array());
        assert_eq!(mac, MacAddress8::new(mac.to_array()));
    }
}
