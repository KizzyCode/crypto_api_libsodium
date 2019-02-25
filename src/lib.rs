//! This crate implements the [`crypto_api`](https://github.com/KizzyCode/crypto_api) with
//! [libsodium](https://github.com/jedisct1/libsodium) as backend


/// Checks if `$condition` evaluates to `true` and returns `$error` if this is not the case
#[macro_export] macro_rules! check {
	($condition:expr, $error:expr) => (if !$condition { Err($error)? });
}
/// Calls a libsodium function
#[macro_export] macro_rules! sodium {
	($($arg:expr),* => $func:expr) => ({
		unsafe {
			assert!(sodium_init() >= 0, "Failed to initialize libsodium");
			($func)($($arg as _),*)
		}
	});
}


// Mods
mod sodium_bindings;
pub mod cipher;
pub mod pbkdf;
pub mod rng;


// Uses and reexports
pub use crate::{ cipher::Ciphers, pbkdf::Pbkdfs, rng::SystemRng };
pub use crypto_api;
use std::{ error::Error, fmt::{ Display, Formatter, Result as FmtResult } };


/// A `CryptoProto`-related error
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum LibsodiumError {
	/// Invalid data (e.g. wrong format, invalid MAC etc.)
	InvalidData,
	/// Not enough resources to perform operation
	ResourceError,
	/// API misuse
	ApiMisuse(&'static str),
	/// The operation may be valid but not in this state
	InvalidState,
	/// Unsupported algorithm/parameter/etc.
	Unsupported
}
impl Display for LibsodiumError {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "{:?}", self)
	}
}
impl Error for LibsodiumError {}
unsafe impl Send for LibsodiumError {}