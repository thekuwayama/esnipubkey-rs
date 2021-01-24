# esnipubkey-rs

[![Actions Status](https://github.com/thekuwayama/esnipubkey-rs/workflows/CI/badge.svg)](https://github.com/thekuwayama/esnipubkey-rs/actions?workflow=CI)
[![MIT licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://raw.githubusercontent.com/thekuwayama/esnipubkey-rs/master/LICENSE.txt)

`esnipubkey-rs` is CLI to fetch ESNI public key.


## Install

You can install `esnipubkey-rs` with the following:

```bash
$ cargo install --git https://github.com/thekuwayama/esnipubkey-rs.git --branch main
```


## Usage

```
$ esnipubkey --help
esnipubkey 0.1.0
CLI to fetch ESNI public key

USAGE:
    esnipubkey [FLAGS] <name>

FLAGS:
    -h, --help       Prints help information
        --hex        Prints ESNIKeys in hex
    -V, --version    Prints version information

ARGS:
    <name>    Query Name
```

```bash
$ esnipubkey cloudflare.com
ESNIKeys {
    version: "ff01",
    checksum: "[01, 02, 03, 04]",
    keys: [
        KeyShareEntry {
            group: 29,
            key_exchange: "[01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01, 01]",
        }
    ],
    cipher_suites: "[(13, 01)]",
    padded_length: 260,
    not_before: "Sat, 26 Dec 2020 04:00:00 +0900",
    not_after: "Fri, 01 Jan 2021 04:00:00 +0900",
    extensions: [],
}
```


## Note

refer: [Before ECH there was (and is!) ESNI](https://blog.cloudflare.com/encrypted-client-hello/#before-ech-there-was-and-is-esni)


## License

The CLI is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
