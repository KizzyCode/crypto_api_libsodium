use crypto_api::pbkdf::{ PbkdfInfo, MemoryHardPbkdfInfo };
use crypto_api_libsodium::{ LibsodiumError, Pbkdfs };
use std::{ usize, u64 };


/// A helper macro to compare a `Box<dyn Error + 'static>` to a `LibsodiumError`
macro_rules! compare_err {
	($err:expr, $expected:expr) => (
		assert_eq!(*$err.downcast_ref::<LibsodiumError>().unwrap(), $expected)
	);
}


/// The maximum memory limit to test against
const MEM_MAX: usize = 2 * 1024 * 1024 * 1024;


/// A trait to extend the info-structs with the ability to test them
trait PropertyTest {
	fn test(&self);
}
impl PropertyTest for PbkdfInfo {
	fn test(&self) {
		// Create PBKDF
		let pbkdf = Pbkdfs::from_name(self.name).unwrap().pbkdf();
		
		// Test against `info()`
		assert_eq!(*self, pbkdf.info());
		
		
		// Macro for easier test calls
		macro_rules! t {
			($l0:expr, $l1:expr, $l2:expr, $a3:expr) => ({
				let (mut a0, a1, a2) = (vec![0u8; $l0], vec![0u8; $l1], vec![0u8; $l2]);
				pbkdf.derive(&mut a0, &a1, &a2, $a3).unwrap_err()
			});
			(0: $l0:expr)=>(t!($l0, self.password_len_min, self.salt_len_min, self.cpu_cost));
			(1: $l1:expr)=>(t!(self.output_len_min, $l1, self.salt_len_min, self.cpu_cost));
			(2: $l2:expr)=>(t!(self.output_len_min, self.password_len_min, $l2, self.cpu_cost));
			(3: $a3:expr)=>(t!(self.output_len_min, self.password_len_min, self.salt_len_min, $a3));
		};
		
		// Test buffer length
		if self.output_len_min > 0 {
			let err = t!(0: self.output_len_min - 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Buffer is too small"))
		}
		if self.output_len_max < MEM_MAX {
			let err = t!(0: self.output_len_max + 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Buffer is too large"))
		}
		
		// Test password length
		if self.password_len_min > 0 {
			let err = t!(1: self.password_len_min - 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Password is too short"))
		}
		if self.password_len_max < MEM_MAX {
			let err = t!(1: self.password_len_max + 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Password is too long"))
		}
		
		// Test salt length
		if self.salt_len_min > 0 {
			let err = t!(2: self.salt_len_min - 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Salt is too short"))
		}
		if self.salt_len_max < MEM_MAX {
			let err = t!(2: self.salt_len_max + 1);
			compare_err!(err, LibsodiumError::ApiMisuse("Salt is too long"))
		}
		
		// Test CPU cost
		if self.cpu_cost_min > 0 {
			let err = t!(3: self.cpu_cost_min - 1);
			compare_err!(err, LibsodiumError::ApiMisuse("CPU cost is too small"))
		}
		if self.cpu_cost_max < u64::MAX {
			let err = t!(3: self.cpu_cost_max + 1);
			compare_err!(err, LibsodiumError::ApiMisuse("CPU cost is too large"))
		}
		
		
		// Test memory hard PBKDF constraints if available
		if let Some(info) = self.memory_hard_pbkdf_info {
			// Create memory hard PBKDF and unwrap specific info
			let pbkdf =
				Pbkdfs::from_name(self.name).unwrap().memory_hard_pkdf().unwrap();
			
			// Macro for easier test calls
			macro_rules! t {
				($a4:expr, $a5:expr) => ({
					pbkdf.derive_memory_hard(
						&mut vec![0u8; self.output_len_min], &vec![0u8; self.password_len_min],
						&vec![0u8; self.salt_len_min], self.cpu_cost_min, $a4, $a5
					).unwrap_err()
				});
				(4: $a4:expr)=>(t!($a4, info.parallelism));
				(5: $a5:expr)=>(t!(info.memory_cost, $a5));
			};
			
			// Test memory cost
			if info.memory_cost_min > 0 {
				let err = t!(4: info.memory_cost_min - 1);
				compare_err!(err, LibsodiumError::ApiMisuse("Memory cost is too small"))
			}
			if info.memory_cost_max < u64::MAX {
				let err = t!(4: info.memory_cost_max + 1);
				compare_err!(err, LibsodiumError::ApiMisuse("Memory cost is too large"))
			}
			
			// Test memory cost
			if info.parallelism_min > 0 {
				let err = t!(5: info.parallelism_min - 1);
				compare_err!(err, LibsodiumError::ApiMisuse("Parallelism-degree is too small"))
			}
			if info.parallelism_max < u64::MAX {
				let err = t!(5: info.parallelism_max + 1);
				compare_err!(err, LibsodiumError::ApiMisuse("Parallelism-degree is too large"))
			}
		}
	}
}


/// A test vector to test a PBKDF
struct PbkdfTestVector {
	pub name: &'static str,
	
	pub password: &'static[u8],
	pub salt: &'static[u8],
	pub cpu_cost: u64,
	pub derived: &'static[u8]
}
impl PbkdfTestVector {
	pub fn test(&self) {
		// Create PBKDF if possible
		let pbkdf = Pbkdfs::from_name(self.name).unwrap().pbkdf();
		
		// Derive key and compare result
		let mut buf = vec![0u8; self.derived.len()];
		pbkdf.derive(&mut buf, self.password, self.salt, self.cpu_cost).unwrap();
		assert_eq!(buf, self.derived);
	}
}


/// A test vector to test a memory hard PBKDF
struct MemoryHardPbkdfTestVector {
	pub name: &'static str,
	
	pub password: &'static[u8],
	pub salt: &'static[u8],
	pub cpu_cost: u64,
	pub memory_cost: u64,
	pub parallelism: u64,
	pub derived: &'static[u8]
}
impl MemoryHardPbkdfTestVector {
	pub fn test(&self) {
		// Create PBKDF if possible
		let pbkdf =
			Pbkdfs::from_name(self.name).unwrap().memory_hard_pkdf().unwrap();
		
		// Derive key and compare result
		let mut buf = vec![0u8; self.derived.len()];
		pbkdf.derive_memory_hard(
			&mut buf, self.password,
			self.salt, self.cpu_cost, self.memory_cost, self.parallelism
		).unwrap();
		assert_eq!(buf, self.derived);
	}
}


#[test]
fn test() {
	PbkdfInfo {
		name: "Argon2iV13",
		output_len_min: 16, output_len_max: 4294967295,
		password_len_min: 0, password_len_max: 4294967295,
		salt_len_min: 16, salt_len_max: 16,
		cpu_cost: 8, cpu_cost_min: 3, cpu_cost_max: 4294967295,
		memory_hard_pbkdf_info: Some(MemoryHardPbkdfInfo {
			memory_cost: 536870912, memory_cost_min: 8192,
			memory_cost_max: match usize::MAX as u64 {
				m if m >= 4398046510080 => 4398046510080,
				m if m >= 2147483648 => 2147483648,
				_ => 32768
			},
			parallelism: 1, parallelism_min: 1, parallelism_max: 1
		})
	}.test();
	
	PbkdfInfo {
		name: "Argon2idV13",
		output_len_min: 16, output_len_max: 4294967295,
		password_len_min: 0, password_len_max: 4294967295,
		salt_len_min: 16, salt_len_max: 16,
		cpu_cost: 4, cpu_cost_min: 1, cpu_cost_max: 4294967295,
		memory_hard_pbkdf_info: Some(MemoryHardPbkdfInfo {
			memory_cost: 1073741824, memory_cost_min: 8192,
			memory_cost_max: match usize::MAX as u64 {
				m if m >= 4398046510080 => 4398046510080,
				m if m >= 2147483648 => 2147483648,
				_ => 32768
			},
			parallelism: 1, parallelism_min: 1, parallelism_max: 1
		})
	}.test();
	
	
	PbkdfTestVector {
		name: "Argon2iV13",
		password: b"Testolope",
		salt: b"nN9Q4NaGZf5eE5YA",
		cpu_cost: 4,
		derived: b"\xa9\xae\xff\xe2\x50\x79\xc7\x34\xb1\xfa\x8a\xe3\x80\xe9\x80\x98\x89\x21\xcf\xde\xc0\x1a\x28\x48"
	}.test();
	
	PbkdfTestVector {
		name: "Argon2iV13",
		password: b"7",
		salt: b"A2ZKsdVSLkL2iozy",
		cpu_cost: 8,
		derived: b"\x93\x60\xe4\xa1\xd5\xff\x87\x8c\x55\x83\xa3\xd4\x0e\xe2\x00\xad\x7b"
	}.test();
	
	PbkdfTestVector {
		name: "Argon2idV13",
		password: b"Testolope",
		salt: b"nN9Q4NaGZf5eE5YA",
		cpu_cost: 4,
		derived: b"\x3d\xa7\xa7\xc3\x92\xae\x89\x18\x41\x0d\x2f\x40\x1d\x6b\xfa\xe0\x96\x54\x68\x73\xcf\x03\x20\x78"
	}.test();
	
	PbkdfTestVector {
		name: "Argon2idV13",
		password: b"7",
		salt: b"A2ZKsdVSLkL2iozy",
		cpu_cost: 8,
		derived: b"\x94\x5e\xd2\x14\x94\x89\xf2\xa1\xb8\x16\x45\x4f\xc6\x17\x68\xab\xc8"
	}.test();
	
	
	MemoryHardPbkdfTestVector {
		name: "Argon2iV13",
		password: b"Testolope",
		salt: b"nN9Q4NaGZf5eE5YA",
		cpu_cost: 4, memory_cost: 1073741824, parallelism: 1,
		derived: b"\x35\xa7\xff\x47\x6f\x24\x62\xe2\x68\x1e\x0b\x9c\x3b\x80\x77\x1b\x5c\x44\x34\x9f\x0b\x98\xe1\x55"
	}.test();
	
	MemoryHardPbkdfTestVector {
		name: "Argon2iV13",
		password: b"7",
		salt: b"A2ZKsdVSLkL2iozy",
		cpu_cost: 8, memory_cost: 1073741824, parallelism: 1,
		derived: b"\xc6\x7b\x88\xa3\x3a\x1f\xe0\xda\x39\xaf\x9e\x0b\xc4\x93\x25\xda\x09"
	}.test();
	
	MemoryHardPbkdfTestVector {
		name: "Argon2idV13",
		password: b"Testolope",
		salt: b"nN9Q4NaGZf5eE5YA",
		cpu_cost: 4, memory_cost: 402653184, parallelism: 1,
		derived: b"\x90\x9f\x5c\x58\x34\x35\xe5\xad\x98\x72\xb6\x11\x1e\xfe\xdd\x25\x1d\xe6\xf7\x43\xfd\x6d\xad\x68"
	}.test();
	
	MemoryHardPbkdfTestVector {
		name: "Argon2idV13",
		password: b"7",
		salt: b"A2ZKsdVSLkL2iozy",
		cpu_cost: 8, memory_cost: 268435456, parallelism: 1,
		derived: b"\xf8\x79\xf2\xb5\xf4\x56\x2e\xff\xfa\x17\x65\x65\xd0\x65\x9f\xc8\xb1"
	}.test();
}