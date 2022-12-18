[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/Salsa.NET/blob/main/LICENSE)

# Salsa.NET

A .NET implementation of [Salsa20](https://cr.yp.to/snuffle/salsafamily-20071225.pdf), [Salsa20/12](https://cr.yp.to/snuffle/salsafamily-20071225.pdf), and [Salsa20/8](https://cr.yp.to/snuffle/salsafamily-20071225.pdf).

> **Warning**
>
> - You'd be better off using Salsa20 from [libsodium](https://doc.libsodium.org/advanced/stream_ciphers/salsa20).
> - The nonce **MUST NOT** be repeated or reused with the same key.
> - Do **NOT** touch the counter unless you know how Salsa20 works internally.
> - I do **NOT** recommend Salsa20/8; the security margin is [not enough](https://eprint.iacr.org/2007/472.pdf). Stick with Salsa20.
