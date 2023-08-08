#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha1::Sha1;

use attrs::{StunAttrs, StunAttrsIter};
use eyre::{Result, eyre};

pub mod attr;
pub mod attrs;
use attr::StunAttr;

pub enum StunAuth<'i> {
	NoAuth,
	Static {
		username: &'i str,
		realm: Option<&'i str>,
		password: &'i str
	},
	Get(&'i dyn Fn(&str, Option<&str>) -> Option<&'i str>)
}

#[derive(Debug, Clone, Copy)]
pub enum StunType {
	Req(u16), // These are actually u12.  Please don't fill it with a u16
	Ind(u16),
	Res(u16),
	Err(u16)
}
impl StunType {
	pub fn method(&self) -> u16 {
		let ret = match self {
			Self::Req(m) => m,
			Self::Ind(m) => m,
			Self::Res(m) => m,
			Self::Err(m) => m,
		}.clone();
		if ret > 0xFFF { panic!("Invalid STUN method inside StunType."); }
		ret
	}
	pub fn is_response(&self) -> bool{
		match self {
			Self::Res(_) | Self::Err(_) => true,
			_ => false
		}
	}
}
impl TryFrom<u16> for StunType {
	type Error = eyre::Report;
	fn try_from(value: u16) -> Result<Self, Self::Error> {
		if value >= 0x4000 { Err(eyre!("Not a STUN class + method.")) }
		else {
			let kind = value & 0b00_00000_1_000_1_0000;
			let method = 
				((0b00_00000_0_000_0_1111 & value) >> 0) |
				((0b00_00000_0_111_0_0000 & value) >> 1) |
				((0b00_11111_0_000_0_0000 & value) >> 2);
			Ok(match kind {
				0b00_000000_0_000_0_0000 => Self::Req(method),
				0b00_000000_0_000_1_0000 => Self::Ind(method),
				0b00_000000_1_000_0_0000 => Self::Res(method),
				0b00_000000_1_000_1_0000 => Self::Err(method),
				_ => unreachable!()
			})
		}
	}
}
impl From<StunType> for u16 {
	fn from(value: StunType) -> Self {
		let method = value.method();
		((0b00_00000_0_000_0_1111 & method) << 0) |
		((0b00_00000_0_111_0_0000 & method) << 1) |
		((0b00_11111_0_000_0_0000 & method) << 2) |
		match value {
			StunType::Req(_) => 0b00_00000_0_000_0_0000,
			StunType::Ind(_) => 0b00_00000_0_000_1_0000,
			StunType::Res(_) => 0b00_00000_1_000_0_0000,
			StunType::Err(_) => 0b00_00000_1_000_1_0000
		}
	}
}

#[derive(Debug, Clone)]
pub struct Stun<'i> {
	pub typ: StunType,
	pub txid: &'i [u8; 12],
	pub attrs: StunAttrs<'i>
}
impl<'i, 'a> IntoIterator for &'a Stun<'i> {
	type Item = StunAttr<'i>;
	type IntoIter = StunIter<'i, 'a>;
	fn into_iter(self) -> Self::IntoIter {
		StunIter {
			integrity: false,
			fingerprint: false,
			attrs: self.attrs.into_iter()
		}
	}
}

pub struct StunIter<'i, 'a> {
	integrity: bool,
	fingerprint: bool,
	attrs: StunAttrsIter<'i, 'a>
}
impl<'i, 'a> Iterator for StunIter<'i, 'a> {
	type Item = StunAttr<'i>;
	fn next(&mut self) -> Option<Self::Item> {
		let attr = self.attrs.next()?.unwrap();
		match attr {
			_ if self.fingerprint => return None,
			StunAttr::Fingerprint(_) => self.fingerprint = true,
			_ if self.integrity => return None,
			StunAttr::Integrity(_) => self.integrity = true,
			_ => {}
		}
		Some(attr)
	}
}

impl<'i> Stun<'i> {
	pub fn decode(buffer: &'i [u8], auth: StunAuth<'_>) -> Result<Self> {
		if buffer.len() < 20 { return Err(eyre!("Packet length ({}) is too short to be a STUN packet.", buffer.len())); }
		let typ = u16::from_be_bytes(buffer[0..][..2].try_into().unwrap());
		let typ = StunType::try_from(typ)?;

		let length = u16::from_be_bytes(buffer[2..][..2].try_into().unwrap());
		if length % 4 != 0 { return Err(eyre!("STUN length ({length}) was not 4-byte aligned.")); }
		if buffer.len() != 20 + length as usize { return Err(eyre!("STUN length ({length}) doesn't match the packet length ({}).", buffer.len())); }

		let magic = u32::from_be_bytes(buffer[4..][..4].try_into().unwrap());
		if magic != 0x2112A442 { return Err(eyre!("Wrong STUN magic value (${magic:x}).")); }

		let txid = (&buffer[8..][..12]).try_into().unwrap();
		let xor_bytes = (&buffer[4..][..16]).try_into().unwrap();

		let attrs = StunAttrs::Parse { buff: &buffer[20..][..length as usize], xor_bytes };

		let mut username = None;
		let mut realm = None;
		let mut integrity = false;

		// let mut seen_typs = HashSet::new();
		let mut i = 0;
		for attr in &attrs {
			let attr = attr?;
			
			i += attr.len();
			while i % 4 != 0 { i += 1; }

			match attr {
				StunAttr::Fingerprint(f) => {
					let mut expected = crc32fast::Hasher::new();
					expected.update(&buffer[..2]);
					expected.update(&i.to_be_bytes());
					expected.update(&buffer[4..][..20 - 4 + i as usize - 8]);
					let expected = expected.finalize() ^ 0x5354554e;
					if f != expected {
						return Err(eyre!("STUN fingerprint check failed"));
					}
					break; // Nothing comes after the Fingerprint
				}
				_ if integrity => {} // The only attribute that can come after integrity is the fingerprint
				StunAttr::Integrity(integrity_buff) => {
					let (username, realm, password) = match (&auth, username, realm) {
						(StunAuth::Static { username, realm, password }, _, _) => {
							(*username, *realm, *password)
						},
						(StunAuth::Get(getter), Some(username), realm) => {
							let Some(password) = getter(username, realm) else {
								return Err(eyre!("StunAuth::Get returned no password for these credentials"))
							};
							(username, realm, password)
						}
						_ => return Err(eyre!("StunAuth auth failure."))
					};

					let md5_data;
					let key_data = if let Some(realm) = realm {
						let mut ctx = md5::Context::new();
						ctx.consume(username.as_bytes());
						ctx.consume(b":");
						ctx.consume(realm.as_bytes());
						ctx.consume(b":");
						ctx.consume(password.as_bytes());
						md5_data = ctx.compute().0;
						&md5_data
					} else {
						password.as_bytes()
					};

					let mut hmac = Hmac::<Sha1>::new_from_slice(key_data).expect("oops");
					hmac.update(&buffer[..2]);
					hmac.update(&length.to_be_bytes());
					hmac.update(&buffer[4..][..(20 - 4) + length as usize - 4 - 20]);

					hmac.verify_slice(integrity_buff.as_ref())?;

					integrity = true;
				},
				StunAttr::Username(s) if username.is_none() => username = Some(s),
				StunAttr::Realm(s) if realm.is_none() => realm = Some(s),
				_ => {}
			}
		}

		Ok(Self {
			typ, txid, attrs
		})
	}
	pub fn encode(&self, buff: &mut [u8], auth: StunAuth<'_>, fingerprint: bool) -> Result<usize> {
		let orig_length = self.attrs.len();
		let mut length = orig_length;

		if let StunAuth::Static {..} = auth { length += 4 + 20; }
		if fingerprint { length += 8; }

		let len = 20 + length;

		if buff.len() < len as usize { return Err(eyre!("Buffer isn't large enough to contain this message.")) }

		buff[0..][..2].copy_from_slice(&u16::from(self.typ).to_be_bytes());
		buff[2..][..2].copy_from_slice(&length.to_be_bytes());
		buff[4..][..4].copy_from_slice(&0x2112A442u32.to_be_bytes());
		buff[8..][..12].copy_from_slice(self.txid);

		let xor_bytes = <[u8; 16]>::try_from(&buff[4..][..16]).unwrap();

		self.attrs.encode(&mut buff[20..][..orig_length as usize], &xor_bytes);

		if let StunAuth::Static { username, realm, password } = auth {
			length += 24;

			let md5_data;
			let key_data = if let Some(realm) = realm {
				let mut ctx = md5::Context::new();
				ctx.consume(username.as_bytes());
				ctx.consume(b":");
				ctx.consume(realm.as_bytes());
				ctx.consume(b":");
				ctx.consume(password.as_bytes());
				md5_data = ctx.compute().0;
				&md5_data
			} else {
				password.as_bytes()
			};

			let mut hmac = Hmac::<Sha1>::new_from_slice(key_data)?;
			hmac.update(&buff[..2]);
			hmac.update(&length.to_be_bytes());
			hmac.update(&buff[4..][..(20 - 4) + length as usize - 4 - 20]);
			let integrity = hmac.finalize().into_bytes();
			StunAttr::Integrity(integrity.as_slice().try_into().unwrap()).encode(&mut buff[20 + length as usize..][..24], &xor_bytes);
		}

		Ok(len as usize)
	}
}
