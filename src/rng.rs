use crate::{ LibsodiumError, sodium_bindings::{ sodium_init, randombytes_buf } };
use std::{ ptr, error::Error, os::raw::{ c_uchar, c_int, c_ulonglong } };
use crypto_api::rng::Rng;


/// The operating system's cryptographically secure RNG
pub struct SystemRng;
impl Rng for SystemRng {
	fn is_secure(&self) -> bool {
		true
	}
	
	fn random(&mut self, buf: &mut[u8]) -> Result<(), Box<dyn Error>> {
		sodium!(buf.as_mut_ptr(), buf.len() => randombytes_buf);
		Ok(())
	}
}