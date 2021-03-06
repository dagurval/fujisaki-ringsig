# fujisaki-ringsig
[![Version](https://img.shields.io/crates/v/fujisaki_ringsig.svg)](https://crates.io/crates/fujisaki_ringsig)
[![Docs](https://docs.rs/fujisaki_ringsig/badge.svg)](https://docs.rs/fujisaki_ringsig)
[![Build Status](https://travis-ci.org/rozbb/fujisaki-ringsig.svg?branch=master)](https://travis-ci.org/rozbb/fujisaki-ringsig)


This is an implementation of the [Traceable Ring Signature algorithm by Eiichiro Fujisaki and
Koutarou Suzuki](https://eprint.iacr.org/2006/389.pdf). This crate uses the `curve25519-dalek`
library. In particular, it uses the `ristretto` module for its elligator implementation.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your choice.

## Warning
This crate should not be used in any serious contexts. It is not secure.

## C-bindings

To generate C-bindings, run `./generate-c-header.sh`. See examples of C bindings
in `example` folder.

To build examples written in C

```bash
cd examples
mkdir build
cd build
cmake -GNinja ..
ninja
```
