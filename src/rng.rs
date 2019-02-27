use crate::sodium_bindings::{ sodium_init, randombytes_buf };
use std::error::Error;
use crypto_api::rng::SecureRng;


/// The operating system's cryptographically secure RNG
pub struct SystemRng;
impl SecureRng for SystemRng {
	fn random(&mut self, buf: &mut[u8]) -> Result<(), Box<dyn Error>> {
		sodium!(buf.as_mut_ptr(), buf.len() => randombytes_buf);
		Ok(())
	}
}