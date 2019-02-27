# Crypto API (libsodium)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Travis-CI](https://travis-ci.org/KizzyCode/crypto_api_libsodium.svg?branch=master)](https://travis-ci.org/KizzyCode/crypto_api_libsodium)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/KizzyCode/crypto_api_libsodium?svg=true)](https://ci.appveyor.com/project/KizzyCode/crypto-api-libsodium)

This crate implements the [`crypto_api`](https://github.com/KizzyCode/crypto_api) with
[libsodium](https://github.com/jedisct1/libsodium) as backend.


## Implemented Primitives
The following `crypto_api`/[libsodium](https://github.com/jedisct1/libsodium) primitives are covered:


### Ciphers

#### Normal Ciphers
- [x] [ChaCha20 (IETF-version)](https://tools.ietf.org/html/rfc7539)
- [ ] [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)

#### AEAD Ciphers
- [x] [AES-256-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [x] [ChaCha20-Poly1305 (IETF-version)](https://tools.ietf.org/html/rfc7539)
- [ ] [XChaCha20-Poly1305](https://download.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)

#### Streaming API
- [ ] [ChaCha20 (IETF-version)](https://tools.ietf.org/html/rfc7539)
- [ ] [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)


### Hashes

#### Stateless API
- [ ] [SHA2-256](https://tools.ietf.org/html/rfc6234)
- [ ] [SHA2-512](https://tools.ietf.org/html/rfc6234)

#### Variable Length Stateless API
- [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)

#### Streaming API
- [ ] [SHA2-256](https://tools.ietf.org/html/rfc6234)
- [ ] [SHA2-512](https://tools.ietf.org/html/rfc6234)

#### Variable Length Streaming API
- [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)


### KDFs
- [ ] [HKDF](https://tools.ietf.org/html/rfc5869) SHA2-256
- [ ] [HKDF](https://tools.ietf.org/html/rfc5869) SHA2-512
- [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)


### MACs

#### Stateless MAC API
- [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-256
- [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-512
- [ ] [Poly1305](https://tools.ietf.org/html/rfc7539)
- [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)

#### Streaming MAC API
- [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-256
- [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-512
- [ ] [Poly1305](https://tools.ietf.org/html/rfc7539)
- [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)


### PBKDFs

#### Memory-Hard PBKDFs
- [x] [Argon2i v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)
- [x] [Argon2id v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)


### RNGs

#### Cryptographically Secure RNGs
- [x] The operating system's cryptographically secure RNG
- [ ] A deterministic cryptographically secure RNG


### Asymmetric Signers
- [x] [Ed25519](https://tools.ietf.org/html/rfc8032)