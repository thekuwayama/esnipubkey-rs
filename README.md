# esnipubkey-rs

[![Actions Status](https://github.com/thekuwayama/esnipubkey-rs/workflows/CI/badge.svg)](https://github.com/thekuwayama/esnipubkey-rs/actions?workflow=CI)
[![MIT licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://raw.githubusercontent.com/thekuwayama/esnipubkey-rs/master/LICENSE.txt)

`esnipubkey-rs` is CLI to fetch ESNI public key.


## Usage

You can build and run `esnipubkey-rs` with the following:

```bash
$ git clone git@github.com:thekuwayama/esnipubkey-rs.git

$ cd esnipubkey-rs

$ cargo build

$ ./target/debug/esnipubkey --help
esnipubkey 0.1.0
CLI to fetch ESNI public key

USAGE:
    esnipubkey-rs <name>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <name>    Query Name
```

```bash
$ ./target/debug/esnipubkey cloudflare.com
ESNIKeys { version: 65281, checksum: [1, 2, 3, 4], keys: [KeyShareEntry { group: 29, key_exchangeok: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] }], cipher_suites: [(19, 1)], padded_length: 260, not_before: 1608922800, not_after: 1609441200, extensions: [] }
```


## Note

[Before ECH there was (and is!) ESNI](https://blog.cloudflare.com/encrypted-client-hello/#before-ech-there-was-and-is-esni)


## License

The CLI is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
