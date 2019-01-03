[![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)


# Crypto API (libsodium)
This crate implements the [`crypto_api`](https://github.com/KizzyCode/crypto_api) with
[libsodium](https://github.com/jedisct1/libsodium) as backend.


## Primitives covered
The following `crypto_api`/libsodium primitives are covered:
 
 [ ] Ciphers
   [ ] Normal ciphers
     [x] [ChaCha20 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
     [ ] [Salsa20](https://cr.yp.to/snuffle.html)
     [ ] [ChaCha20](https://cr.yp.to/chacha.html)
     [ ] [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20081128.pdf)
     [ ] [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)
   
   [x] AEAD ciphers
     [x] [AES-256-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
     [x] [ChaCha20+Poly1305 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
   
   [ ] Streaming API
     [ ] [ChaCha20 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
     [ ] [Salsa20](https://cr.yp.to/snuffle.html)
     [ ] [ChaCha20](https://cr.yp.to/chacha.html)
     [ ] [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20081128.pdf)
     [ ] [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)
   
   [ ] AEAD Streaming API
     [ ] [ChaCha20+Poly1305 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
   	 

 [ ] Hash
   [ ] Normal hash
     [ ] [SHA2-256](https://tools.ietf.org/html/rfc6234)
     [ ] [SHA2-512](https://tools.ietf.org/html/rfc6234)
   
   [ ] Variable-length hash
     [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)
   
   [ ] Streaming API
     [ ] [SHA2-256](https://tools.ietf.org/html/rfc6234)
     [ ] [SHA2-512](https://tools.ietf.org/html/rfc6234)
   
   [ ] Variable-length Streaming API
     [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)
   
   
 
 [ ] KDF
   [ ] Normal parametrized KDF (tweaked with salt/info)
     [ ] [HKDF](https://tools.ietf.org/html/rfc5869) SHA2-256
     [ ] [HKDF](https://tools.ietf.org/html/rfc5869) SHA2-512
     [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)
   
 
 [ ] MAC
   [ ] Normal MAC
     [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-256
     [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-512
     [ ] [Poly1305](https://tools.ietf.org/html/rfc7539)
     [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)
   
   [ ] Streaming API
     [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-256
     [ ] [HMAC](https://tools.ietf.org/html/rfc4868) SHA2-512
     [ ] [Poly1305](https://tools.ietf.org/html/rfc7539)
     [ ] [Blake2b](https://tools.ietf.org/html/rfc7693)   
 
 
 [ ] PBKDF
   [ ] Memory-hard PBKDF
     [ ] [Argon2i v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)
     [ ] [Argon2id v2.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)