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
        .expect("Falid: not specify domain name");

    let bytes = esnipubkey::fetch(name).expect("Faild: resolve domain name");
    print!("{}", bytes.iter().map(|c| format!("{:02x?}", c)).collect::<Vec<_>>().join(" "));
}
