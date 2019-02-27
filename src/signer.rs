use crate::{
	LibsodiumError,
	sodium_bindings::{
		sodium_init, crypto_sign_ed25519_keypair, crypto_sign_ed25519_sk_to_pk,
		crypto_sign_ed25519_detached, crypto_sign_ed25519_verify_detached,
		crypto_sign_ed25519_BYTES,
		crypto_sign_ed25519_SECRETKEYBYTES, crypto_sign_ed25519_PUBLICKEYBYTES
	}
};
use std::{
	ptr, error::Error,
	os::raw::{ c_uchar, c_int, c_ulonglong }
};
use crypto_api::{
	rng::{ SecKeyGen, PubKeyGen },
	signer::{ SignerInfo, Signer }
};


/// An Ed25519 implementation
struct Ed25519 {
	pub signer: Signers,
	
	pub sign: unsafe extern "C" fn(
		sig: *mut c_uchar, siglen_p: *mut c_ulonglong,
		m: *const c_uchar, mlen: c_ulonglong,
		sk: *const c_uchar
	) -> c_int,
	pub verify: unsafe extern "C" fn(
		sig: *const c_uchar, m: *const c_uchar, mlen: c_ulonglong,
		pk: *const c_uchar
	) -> c_int,
	
	pub new_sec_key: unsafe extern "C" fn(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int,
	pub get_pub_key: unsafe extern "C" fn(pk: *mut c_uchar, sk: *const c_uchar) -> c_int
}
impl Signer for Ed25519 {
	fn info(&self) -> SignerInfo {
		SignerInfo {
			name: "Ed25519",
			sig_len: crypto_sign_ed25519_BYTES as usize,
			sec_key_len: crypto_sign_ed25519_SECRETKEYBYTES as usize,
			pub_key_len: crypto_sign_ed25519_PUBLICKEYBYTES as usize
		}
	}
	
	fn sign(&self, buf: &mut[u8], data: &[u8], sec_key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Check parameters
		let info = self.info();
		check!(buf.len() >= info.sig_len, LibsodiumError::ApiMisuse("Buffer is too small"));
		check!(sec_key.len() == info.sec_key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		
		// Sign the data
		assert_eq!(sodium!(
			buf.as_mut_ptr(), ptr::null_mut(), data.as_ptr(), data.len(), sec_key.as_ptr()
				=> self.sign
		), 0);
		Ok(info.sig_len)
	}
	fn verify(&self, data: &[u8], sig: &[u8], pub_key: &[u8])
		-> Result<(), Box<dyn Error + 'static>>
	{
		// Check parameters
		let info = self.info();
		check!(sig.len() == info.sig_len, LibsodiumError::ApiMisuse("Invalid signature length"));
		check!(pub_key.len() == info.pub_key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		
		// Verify the signature
		match sodium!(sig.as_ptr(), data.as_ptr(), data.len(), pub_key.as_ptr() => self.verify) {
			0 => Ok(()),
			_ => Err(LibsodiumError::InvalidData)?
		}
	}
}
impl SecKeyGen for Ed25519 {
	fn new_sec_key(&self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>> {
		// Check the buffer length
		let info = self.info();
		check!(buf.len() >= info.sec_key_len, LibsodiumError::ApiMisuse("Buffer is too small"));
		
		// Generate the key
		let mut _pub_key = vec![0u8; info.pub_key_len];
		assert_eq!(sodium!(_pub_key.as_mut_ptr(), buf.as_mut_ptr() => self.new_sec_key), 0);
		Ok(info.sec_key_len)
	}
}
impl PubKeyGen for Ed25519 {
	fn get_pub_key(&self, buf: &mut[u8], sec_key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>
	{
		// Check the buffer length
		let info = self.info();
		check!(buf.len() >= info.pub_key_len, LibsodiumError::ApiMisuse("Buffer is too small"));
		check!(sec_key.len() == info.sec_key_len, LibsodiumError::ApiMisuse("Invalid key length"));
		
		// Compute the public key
		let mut _pub_key = [0u8; crypto_sign_ed25519_PUBLICKEYBYTES as usize];
		assert_eq!(sodium!(buf.as_mut_ptr(), sec_key.as_ptr() => self.get_pub_key), 0);
		Ok(info.pub_key_len)
	}
}


/// Signer implementations
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Signers {
	/// [Ed25519](https://tools.ietf.org/html/rfc8032)
	Ed25519
}
impl Signers {
	/// Selects a signer implementation from name
	///
	/// Currently supported names are:
	///  - `Ed25519` which maps to Ed25519
	pub fn from_name(name: &str) -> Result<Self, LibsodiumError> {
		Ok(match name {
			"Ed25519" => Signers::Ed25519,
			_ => return Err(LibsodiumError::Unsupported)
		})
	}
	
	/// Creates a new `Signer`-instance with this implementation
	pub fn signer(self) -> Box<dyn Signer> {
		match self {
			Signers::Ed25519 => Box::new(Ed25519 {
				signer: self,
				sign: crypto_sign_ed25519_detached, verify: crypto_sign_ed25519_verify_detached,
				new_sec_key: crypto_sign_ed25519_keypair, get_pub_key: crypto_sign_ed25519_sk_to_pk
			})
		}
	}
}