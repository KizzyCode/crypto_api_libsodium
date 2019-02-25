use crate::{
	LibsodiumError,
	sodium_bindings::{
		sodium_init,
		
		crypto_pwhash_argon2i, crypto_pwhash_argon2i_bytes_min, crypto_pwhash_argon2i_bytes_max,
		crypto_pwhash_argon2i_passwd_min, crypto_pwhash_argon2i_passwd_max,
		crypto_pwhash_argon2i_opslimit_min, crypto_pwhash_argon2i_opslimit_max,
		crypto_pwhash_argon2i_memlimit_min, crypto_pwhash_argon2i_memlimit_max,
		crypto_pwhash_argon2i_saltbytes, crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE,
		crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE, crypto_pwhash_argon2i_ALG_ARGON2I13,
		
		crypto_pwhash_argon2id, crypto_pwhash_argon2id_bytes_min, crypto_pwhash_argon2id_bytes_max,
		crypto_pwhash_argon2id_passwd_min, crypto_pwhash_argon2id_passwd_max,
		crypto_pwhash_argon2id_opslimit_min, crypto_pwhash_argon2id_opslimit_max,
		crypto_pwhash_argon2id_memlimit_min, crypto_pwhash_argon2id_memlimit_max,
		crypto_pwhash_argon2id_saltbytes, crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
		crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE, crypto_pwhash_argon2id_ALG_ARGON2ID13
	}
};
use std::{
	error::Error,
	os::raw::{ c_char, c_uchar, c_int, c_ulonglong }
};
use crypto_api::pbkdf::{ Pbkdf, MemoryHardPbkdf, PbkdfInfo, MemoryHardPbkdfInfo };


/// The default parallelism used (because the exposed API always uses `1` :( )
const PARALLELISM: u64 = 1;


/// An Argon2 implementation
struct Argon2 {
	pub pbkdf: Pbkdfs,
	pub algo_id: c_int,
	pub derive: unsafe extern "C" fn(
		out: *mut c_uchar, outlen: c_ulonglong,
		passwd: *const c_char, passwdlen: c_ulonglong, salt: *const c_uchar,
		opslimit: c_ulonglong, memlimit: usize,
		alg: c_int
	) -> c_int
}
impl Pbkdf for Argon2 {
	fn info(&self) -> PbkdfInfo {
		match self.pbkdf {
			Pbkdfs::Argon2iV13 => PbkdfInfo {
				name: "Argon2iV13",
				output_len_min: sodium!(=> crypto_pwhash_argon2i_bytes_min),
				output_len_max: sodium!(=> crypto_pwhash_argon2i_bytes_max),
				
				password_len_min: sodium!(=> crypto_pwhash_argon2i_passwd_min),
				password_len_max: sodium!(=> crypto_pwhash_argon2i_passwd_max),
				
				salt_len_min: sodium!(=> crypto_pwhash_argon2i_saltbytes),
				salt_len_max: sodium!(=> crypto_pwhash_argon2i_saltbytes),
				
				cpu_cost: crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE as u64,
				cpu_cost_min: sodium!(=> crypto_pwhash_argon2i_opslimit_min) as u64,
				cpu_cost_max: sodium!(=> crypto_pwhash_argon2i_opslimit_max) as u64,
				
				memory_hard_pbkdf_info: Some(MemoryHardPbkdfInfo {
					memory_cost: crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE as u64,
					memory_cost_min: sodium!(=> crypto_pwhash_argon2i_memlimit_min) as u64,
					memory_cost_max: sodium!(=> crypto_pwhash_argon2i_memlimit_max) as u64,
				
					parallelism: PARALLELISM,
					parallelism_min: PARALLELISM, parallelism_max: PARALLELISM
				})
			},
			Pbkdfs::Argon2idV13 => PbkdfInfo {
				name: "Argon2idV13",
				output_len_min: sodium!(=> crypto_pwhash_argon2id_bytes_min),
				output_len_max: sodium!(=> crypto_pwhash_argon2id_bytes_max),
				
				password_len_min: sodium!(=> crypto_pwhash_argon2id_passwd_min),
				password_len_max: sodium!(=> crypto_pwhash_argon2id_passwd_max),
				
				salt_len_min: sodium!(=> crypto_pwhash_argon2id_saltbytes),
				salt_len_max: sodium!(=> crypto_pwhash_argon2id_saltbytes),
				
				cpu_cost: crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as u64,
				cpu_cost_min: sodium!(=> crypto_pwhash_argon2id_opslimit_min) as u64,
				cpu_cost_max: sodium!(=> crypto_pwhash_argon2id_opslimit_max) as u64,
				
				memory_hard_pbkdf_info: Some(MemoryHardPbkdfInfo {
					memory_cost: crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as u64,
					memory_cost_min: sodium!(=> crypto_pwhash_argon2id_memlimit_min) as u64,
					memory_cost_max: sodium!(=> crypto_pwhash_argon2id_memlimit_max) as u64,
					
					parallelism: PARALLELISM,
					parallelism_min: PARALLELISM, parallelism_max: PARALLELISM
				})
			}
		}
	}
	
	fn derive(&self, buf: &mut[u8], password: &[u8], salt: &[u8], cpu_cost: u64)
		-> Result<(), Box<dyn Error>>
	{
		// Get the memory hard info and call the memory hard implementation with the default values
		let info = self.info().memory_hard_pbkdf_info.unwrap();
		self.derive_memory_hard(buf, password, salt, cpu_cost, info.memory_cost, info.parallelism)
	}
}
impl MemoryHardPbkdf for Argon2 {
	fn derive_memory_hard(&self, buf: &mut[u8], password: &[u8], salt: &[u8], cpu_cost: u64,
		memory_cost: u64, parallelism: u64) -> Result<(), Box<dyn Error>>
	{
		// Check parameters
		let info = self.info();
		check!(buf.len() >= info.output_len_min, LibsodiumError::ApiMisuse("Buffer is too small"));
		check!(buf.len() <= info.output_len_max, LibsodiumError::ApiMisuse("Buffer is too large"));
		check!(
			password.len() >= info.password_len_min,
			LibsodiumError::ApiMisuse("Password is too short")
		);
		check!(
			password.len() <= info.password_len_max,
			LibsodiumError::ApiMisuse("Password is too long")
		);
		check!(salt.len() >= info.salt_len_min, LibsodiumError::ApiMisuse("Salt is too short"));
		check!(salt.len() <= info.salt_len_max, LibsodiumError::ApiMisuse("Salt is too long"));
		check!(cpu_cost >= info.cpu_cost_min, LibsodiumError::ApiMisuse("CPU cost is too small"));
		check!(cpu_cost <= info.cpu_cost_max, LibsodiumError::ApiMisuse("CPU cost is too large"));
		
		// Check memory hard parameters
		let info = info.memory_hard_pbkdf_info.unwrap();
		check!(
			memory_cost >= info.memory_cost_min,
			LibsodiumError::ApiMisuse("Memory cost is too small")
		);
		check!(
			memory_cost <= info.memory_cost_max,
			LibsodiumError::ApiMisuse("Memory cost is too large")
		);
		check!(
			parallelism >= info.parallelism_min,
			LibsodiumError::ApiMisuse("Parallelism-degree is too small")
		);
		check!(
			parallelism <= info.parallelism_max,
			LibsodiumError::ApiMisuse("Parallelism-degree is too large")
		);
		
		// Derive key
		let result = sodium!(
			buf.as_mut_ptr(), buf.len(), password.as_ptr(), password.len(), salt.as_ptr(),
			cpu_cost, memory_cost, self.algo_id
				=> self.derive
		);
		match result {
			0 => Ok(()),
			-22 | -33 => Err(LibsodiumError::ResourceError)?,
			e => panic!("Completely unexpected Argon2 error \"{}\" o.O", e)
		}
	}
}


/// PBKDF implementations
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Pbkdfs {
	/// [Argon2i v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)
	Argon2iV13,
	/// [Argon2id v1.3](https://www.cryptolux.org/images/0/0d/Argon2.pdf)
	Argon2idV13
}
impl Pbkdfs {
	/// Selects a PBKDF implementation from name
	///
	/// Currently supported names are:
	///  - `Argon2iV13` which maps to Argon2i v1.3
	///  - `Argon2idV13` which maps to Argon2id v1.3
	pub fn from_name(name: &str) -> Result<Self, LibsodiumError> {
		Ok(match name {
			"Argon2iV13" => Pbkdfs::Argon2iV13,
			"Argon2idV13" => Pbkdfs::Argon2idV13,
			_ => return Err(LibsodiumError::Unsupported)
		})
	}
	
	/// Creates a new `Pbkdf`-instance with this implementation
	pub fn pbkdf(self) -> Box<dyn Pbkdf> {
		match self {
			Pbkdfs::Argon2iV13 => Box::new(Argon2 {
				pbkdf: self,
				algo_id: crypto_pwhash_argon2i_ALG_ARGON2I13 as c_int,
				derive: crypto_pwhash_argon2i
			}),
			Pbkdfs::Argon2idV13 => Box::new(Argon2 {
				pbkdf: self,
				algo_id: crypto_pwhash_argon2id_ALG_ARGON2ID13 as c_int,
				derive: crypto_pwhash_argon2id
			})
		}
	}
	/// Creates a new `MemoryHardPbkdf`-instance with this implementation
	pub fn memory_hard_pkdf(self) -> Result<Box<dyn MemoryHardPbkdf>, LibsodiumError> {
		Ok(match self {
			Pbkdfs::Argon2iV13 => Box::new(Argon2 {
				pbkdf: self,
				algo_id: crypto_pwhash_argon2i_ALG_ARGON2I13 as c_int,
				derive: crypto_pwhash_argon2i
			}),
			Pbkdfs::Argon2idV13 => Box::new(Argon2 {
				pbkdf: self,
				algo_id: crypto_pwhash_argon2id_ALG_ARGON2ID13 as c_int,
				derive: crypto_pwhash_argon2id
			})
		})
	}
}