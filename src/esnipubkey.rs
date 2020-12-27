extern crate failure;
extern crate dohc;
extern crate serde;
extern crate base64;

use dohc::doh;
use serde::{Serialize, Deserialize};

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
}
