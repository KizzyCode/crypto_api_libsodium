use crate::{
	LibsodiumError,
	sodium_bindings::{
		sodium_init, crypto_stream_chacha20_ietf_xor,
		crypto_aead_aes256gcm_encrypt, crypto_aead_aes256gcm_decrypt,
		crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_decrypt
	}
};
use std::{ ptr, error::Error, os::raw::{ c_uchar, c_int, c_ulonglong } };
use crypto_api::cipher::{ CipherInfo, Cipher, AeadCipher };


/// An AEAD implementation
struct Aead {
	pub cipher: Ciphers,
	pub encrypt: unsafe extern "C" fn(
		c: *mut c_uchar, clen_p: *mut c_ulonglong,
		m: *const c_uchar, mlen: c_ulonglong,
		ad: *const c_uchar, adlen: c_ulonglong,
		nsec: *const c_uchar, npub: *const c_uchar, k: *const c_uchar
	) -> c_int,
	pub decrypt: unsafe extern "C" fn(
		m: *mut c_uchar, mlen_p: *mut c_ulonglong,
		nsec: *mut c_uchar,
		c: *const c_uchar, clen: c_ulonglong,
		ad: *const c_uchar, adlen: c_ulonglong,
		npub: *const c_uchar, k: *const c_uchar,
	) -> c_int
}
/// A XOR stream cipher implementation
struct Xor {
	pub cipher: Ciphers,
	pub xor: unsafe extern "C" fn(
		c: *mut c_uchar,
		m: *const c_uchar,
		mlen: c_ulonglong,
		n: *const c_uchar,
		k: *const c_uchar,
	) -> c_int
}


impl Cipher for Aead {
	fn info(&self) -> CipherInfo {
		match self.cipher {
			Ciphers::Aes256Gcm => CipherInfo {
				name: "Aes256Gcm", key_len: 32, nonce_len: 12,
				aead_tag_len: Some(16)
			},
			Ciphers::ChaCha20Poly1305Ietf => CipherInfo {
				name: "ChaCha20Poly1305Ietf", key_len: 32, nonce_len: 12,
				aead_tag_len: Some(16)
			},
			_ => unreachable!()
		}
	}
	
	
	fn encrypted_len_max(&self, plaintext_len: usize) -> usize {
		plaintext_len + self.info().aead_tag_len.unwrap()
	}
	
	
	fn encrypt(&self, buf: &mut[u8], plaintext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		self.seal(buf, plaintext_len, &[], key, nonce)
	}
	
	fn decrypt(&self, buf: &mut[u8], ciphertext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		self.open(buf, ciphertext_len, &[], key, nonce)
	}
}
impl AeadCipher for Aead {
	fn seal(&self, buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		// Check variables
		let info = self.info();
		check!(
			buf.len() >= self.encrypted_len_max(plaintext_len),
			LibsodiumError::ApiMisuse("Buffer is too small")
		);
		check!(key.len() == info.key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		check!(nonce.len() == info.nonce_len, LibsodiumError::ApiMisuse("Invalid nonce length"));
		
		// Call libsodium
		assert_eq!(sodium!(
			buf.as_mut_ptr(), ptr::null_mut(), buf.as_ptr(), plaintext_len,
			ad.as_ptr(), ad.len(), ptr::null(), nonce.as_ptr(), key.as_ptr()
				=> self.encrypt
		), 0);
		Ok(plaintext_len + info.aead_tag_len.unwrap())
	}
	
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		// Check variables
		let info = self.info();
		check!(
			buf.len() >= ciphertext_len,
			LibsodiumError::ApiMisuse("Buffer is too small")
		);
		check!(key.len() == info.key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		check!(nonce.len() == info.nonce_len, LibsodiumError::ApiMisuse("Invalid nonce length"));
		
		// Call libsodium
		let result = sodium!(
			buf.as_mut_ptr(), ptr::null_mut(), ptr::null::<*mut c_uchar>(),
			buf.as_ptr(), ciphertext_len, ad.as_ptr(), ad.len(), nonce.as_ptr(), key.as_ptr()
				=> self.decrypt
		);
		check!(result == 0, LibsodiumError::InvalidData);
		Ok(ciphertext_len - info.aead_tag_len.unwrap())
	}
}


impl Cipher for Xor {
	fn info(&self) -> CipherInfo {
		match self.cipher {
			Ciphers::ChaCha20Ietf => CipherInfo {
				name: "ChaCha20Ietf", key_len: 32, nonce_len: 12,
				aead_tag_len: None
			},
			_ => unreachable!()
		}
	}
	
	
	fn encrypted_len_max(&self, plaintext_len: usize) -> usize {
		plaintext_len
	}
	
	
	fn encrypt(&self, buf: &mut[u8], plaintext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		// Check variables
		let info = self.info();
		check!(
			buf.len() >= self.encrypted_len_max(plaintext_len),
			LibsodiumError::ApiMisuse("Buffer is too small")
		);
		check!(key.len() == info.key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		check!(nonce.len() == info.nonce_len, LibsodiumError::ApiMisuse("Invalid nonce length"));
		
		// Call libsodium
		assert_eq!(sodium!(
			buf.as_mut_ptr(), buf.as_ptr(), plaintext_len, nonce.as_ptr(), key.as_ptr()
				=> self.xor
		), 0);
		Ok(plaintext_len)
	}
	
	fn decrypt(&self, buf: &mut[u8], ciphertext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error>>
	{
		self.encrypt(buf, ciphertext_len, key, nonce)
	}
}


/// Cipher implementations
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ciphers {
	/// [AES-256-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
	Aes256Gcm,
	/// [ChaCha20+Poly1305 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
	ChaCha20Poly1305Ietf,
	/// [ChaCha20 (IETF-version, RFC 7539)](https://tools.ietf.org/html/rfc7539)
	ChaCha20Ietf
}
impl Ciphers {
	/// Selects a cipher implementation from name
	///
	/// Currently supported names are:
	///  - `Aes256Gcm` which maps to Aes256Gcm
	///  - `ChaCha20Poly1305Ietf` which maps to ChaCha20Poly1305Ietf
	///  - `ChaCha20Ietf` which maps to ChaCha20Ietf
	pub fn from_name(name: &str) -> Result<Self, LibsodiumError> {
		Ok(match name {
			"Aes256Gcm" => Ciphers::Aes256Gcm,
			"ChaCha20Poly1305Ietf" => Ciphers::ChaCha20Poly1305Ietf,
			"ChaCha20Ietf" => Ciphers::ChaCha20Ietf,
			_ => return Err(LibsodiumError::Unsupported)
		})
	}
	
	/// Creates a new `Cipher`-instance with this implementation
	pub fn cipher(self) -> Box<Cipher> {
		match self {
			Ciphers::Aes256Gcm => Box::new(Aead {
				cipher: self,
				encrypt: crypto_aead_aes256gcm_encrypt,
				decrypt: crypto_aead_aes256gcm_decrypt
			}),
			Ciphers::ChaCha20Poly1305Ietf => Box::new(Aead {
				cipher: self,
				encrypt: crypto_aead_chacha20poly1305_ietf_encrypt,
				decrypt: crypto_aead_chacha20poly1305_ietf_decrypt
			}),
			Ciphers::ChaCha20Ietf => Box::new(Xor {
				cipher: self,
				xor: crypto_stream_chacha20_ietf_xor
			})
		}
	}
	/// Creates a new `AeadCipher`-instance with this implementation
	pub fn aead_cipher(self) -> Result<Box<AeadCipher>, LibsodiumError> {
		Ok(match self {
			Ciphers::Aes256Gcm => Box::new(Aead {
				cipher: self,
				encrypt: crypto_aead_aes256gcm_encrypt,
				decrypt: crypto_aead_aes256gcm_decrypt
			}),
			Ciphers::ChaCha20Poly1305Ietf => Box::new(Aead {
				cipher: self,
				encrypt: crypto_aead_chacha20poly1305_ietf_encrypt,
				decrypt: crypto_aead_chacha20poly1305_ietf_decrypt
			}),
			Ciphers::ChaCha20Ietf => return Err(LibsodiumError::Unsupported)
		})
	}
}