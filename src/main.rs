extern crate clap;

use clap::{App, Arg};

mod esnipubkey;

fn main() {
    let cli = App::new("esnipubkey")
        .version("0.1.0")
        .about("CLI to fetch ESNI public key")
        .arg(Arg::with_name("name").help("Query Name").required(true));
    let matches = cli.get_matches();
    let name = matches
        .value_of("name")
        .expect("Falied: not specify domain name");

    let bytes = esnipubkey::fetch(name).expect("Failed: fetch ESNIKeys");
    let esnikeys = esnipubkey::parse_esnikeys(&bytes).expect("Failed: parse ESNIKeys").1;
    print!("{:?}", esnikeys);
}
