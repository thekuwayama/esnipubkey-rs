#[macro_use]
extern crate clap;

use clap::{App, Arg};

mod esnipubkey;

fn main() {
    let cli = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(Arg::with_name("name").help("Query Name").required(true))
        .arg(
            Arg::with_name("hex")
                .help("Prints ESNIKeys in hex")
                .long("hex")
                .takes_value(false),
        );
    let matches = cli.get_matches();
    let name = matches
        .value_of("name")
        .expect("Falied: not specify domain name");

    let bytes = esnipubkey::fetch(name).expect("Failed: fetch ESNIKeys");
    if matches.is_present("hex") {
        println!(
            "hex: {}",
            bytes
                .iter()
                .map(|c| format!("{:02x?}", c))
                .collect::<Vec<_>>()
                .join(" ")
        );
    } else {
        let esnikeys = esnipubkey::parse_esnikeys(&bytes).expect("Failed: parse ESNIKeys");
        println!("{:#?}", esnikeys);
    }
}
