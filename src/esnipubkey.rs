extern crate base64;
extern crate dohc;
extern crate failure;
extern crate nom;
extern crate serde;

use dohc::doh;
use nom::{
    named,
    do_parse,
    take,
    number::streaming::{be_u8, be_u16, be_u64},
    many0,
    tuple,
    complete,
};
use serde::{Serialize, Deserialize};

#[allow(unused_imports)]
use std::io::Write;

#[derive(Serialize, Deserialize, Debug)]
struct Question {
    name: String,
    r#type: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Answer {
    name: String,
    r#type: i32,
    #[serde(rename(deserialize = "TTL"))]
    ttl: i32,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    #[serde(rename(deserialize = "Status"))]
    status: i32,
    #[serde(rename(deserialize = "TC"))]
    tc: bool,
    #[serde(rename(deserialize = "RD"))]
    rd: bool,
    #[serde(rename(deserialize = "RA"))]
    ra: bool,
    #[serde(rename(deserialize = "AD"))]
    ad: bool,
    #[serde(rename(deserialize = "CD"))]
    cd: bool,
    #[serde(rename(deserialize = "Question"))]
    question: Vec<Question>,
    #[serde(rename(deserialize = "Answer"))]
    answer: Vec<Answer>,
}

pub fn fetch(name: &str) -> Result<Vec<u8>, failure::Error> {
    let json = doh::resolve(&prefix_esni(name), "TXT")?;
    let deserialized: Response = serde_json::from_str(&json)?;
    let bytes = base64::decode(deserialized.answer[0].data.replace("\"", ""))?;

    Ok(bytes)
}

fn prefix_esni(name: &str) -> String {
    if name.starts_with("_esni.") { name.to_string() }
    else { format!("_esni.{}", name) }
}

type NamedGroup = u16;

#[derive(Debug)]
pub struct KeyShareEntry {
    group: NamedGroup,
    key_exchange: Vec<u8>,
}

type CipherSuite = (u8, u8);

#[derive(Debug)]
pub struct ESNIKeys {
    version: u16,
    checksum: [u8; 4],
    keys: Vec<KeyShareEntry>,
    cipher_suites: Vec<CipherSuite>,
    padded_length: u16,
    not_before: u64,
    not_after: u64,
    extensions: Vec<u8>,
}

named!(pub parse_esnikeys<&[u8], ESNIKeys>, do_parse!(
    version: be_u16 >>
    c0: be_u8 >>
    c1: be_u8 >>
    c2: be_u8 >>
    c3: be_u8 >>
    kse_len: be_u16 >>
    kse_payload: take!(kse_len) >>
    cs_len: be_u16 >>
    cs_payload: take!(cs_len) >>
    padded_length: be_u16 >>
    not_before: be_u64 >>
    not_after: be_u64 >>
    ex_len: be_u16 >>
    ex_payload: take!(ex_len) >>
    (ESNIKeys {
        version,
        checksum: [c0, c1, c2, c3],
        keys: parse_key_share_entrys(kse_payload)?.1,
        cipher_suites: parse_cipher_suites(cs_payload)?.1,
        padded_length,
        not_before,
        not_after,
        extensions: ex_payload.into(),
    })        
));

named!(parse_cipher_suites<&[u8], Vec<CipherSuite>>,
    many0!(complete!(tuple!(be_u8, be_u8)))
);

named!(parse_key_share_entry<&[u8], KeyShareEntry>, do_parse!(
    group: be_u16 >>
    ke_len: be_u16 >>
    ke_payload: take!(ke_len) >>
    (KeyShareEntry {
        group,
        key_exchange: ke_payload.into(),
    })
));

named!(parse_key_share_entrys<&[u8], Vec<KeyShareEntry>>,
    many0!(complete!(parse_key_share_entry))
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_esni() {
        assert_eq!(
            prefix_esni("example.com"),
            "_esni.example.com"
        );

        assert_eq!(
            prefix_esni("_esni.example.com"),
            "_esni.example.com"
        );
    }

    #[test]
    fn test_parse_esnikeys() {
        let bytes: Vec<u8> = vec![
            0xff, 0x01, // version
            0x01, 0x02, 0x03, 0x04, // checksum
            0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // keys
            0x00, 0x02, 0x13, 0x01, // cipher_suites
            0x01, 0x04, // padded_length
            0x00, 0x00, 0x00, 0x00, 0x5f, 0xe6, 0x36, 0xb0, // not_before
            0x00, 0x00, 0x00, 0x00, 0x5f, 0xee, 0x1f, 0xb0, // not_after
            0x00, 0x00, // extensions
        ];

        let result = parse_esnikeys(&bytes[..]);
        assert!(result.is_ok());
        let _ = writeln!(&mut std::io::stderr(), "{:?}", result);

        let esnikeys = result.unwrap().1;
        assert_eq!(esnikeys.version, u16::from_str_radix("ff01", 16).unwrap());
        assert_eq!(esnikeys.checksum, [1u8, 2u8, 3u8, 4u8]);
        assert_eq!(esnikeys.cipher_suites, [(19u8, 1u8)]);
        assert_eq!(esnikeys.padded_length, 260);
        assert_eq!(esnikeys.not_before, 1608922800);
        assert_eq!(esnikeys.not_after, 1609441200);
        assert!(esnikeys.extensions.is_empty());
    }
}
