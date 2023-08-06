#![allow(dead_code)]
use std::collections::HashSet;
use std::borrow::Cow;

use eyre::{Result, eyre};

pub mod attr;
use attr::StunAttr;

mod mbedtls_util;

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
	pub txid: Cow<'i, [u8; 12]>,
	pub attrs: Cow<'i, [StunAttr]>
}
impl<'i> Stun<'i> {
	pub fn has_auth(&self) {
		
	}
}

impl<'i> Stun<'i> {
	pub fn parse_auth(buffer: &'i [u8], auth: StunAuth<'_>) -> Result<Self> {
		if buffer.len() < 20 { return Err(eyre!("Packet length ({}) is too short to be a STUN packet.", buffer.len())); }
		let typ = u16::from_be_bytes(buffer[0..][..2].try_into().unwrap());
		let typ = StunType::try_from(typ)?;

		let length = u16::from_be_bytes(buffer[2..][..2].try_into().unwrap());
		if length % 4 != 0 { return Err(eyre!("STUN length ({length}) was not 4-byte aligned.")); }
		if buffer.len() != 20 + length as usize { return Err(eyre!("STUN length ({length}) doesn't match the packet length ({}).", buffer.len())); }

		let magic = u32::from_be_bytes(buffer[4..][..4].try_into().unwrap());
		if magic != 0x2112A442 { return Err(eyre!("Wrong STUN magic value (${magic:x}).")); }

		let txid = Cow::Borrowed(buffer[8..][..12].try_into().unwrap());
		let xor_bytes = &buffer[4..][..16];

		let mut integrity = None;
		let mut fingerprint = None;

		let mut seen_typs = HashSet::new();
		let mut attrs = Vec::new();
		let mut i = 0;
		while i < length {
			let offset = 20 + i as usize;
			let typ = u16::from_be_bytes(buffer[offset..][..2].try_into().unwrap());
			let attr_len = u16::from_be_bytes(buffer[offset + 2..][..2].try_into().unwrap());
			i += 4;

			// println!("{typ} {attr_len}");

			let max_len = length - i;
			if attr_len > max_len { return Err(eyre!("Attribute length ({attr_len}) is longer than the remaining STUN length ({max_len}).")); }

			i += attr_len;

			let val = &buffer[offset + 4..][..attr_len as usize];

			let attr = StunAttr::parse(typ, val, xor_bytes)?;
			while i % 4 != 0 { i += 1; }

			if !seen_typs.contains(&typ) {
				seen_typs.insert(typ);
				match attr {
					_ if fingerprint.is_some() => {}, // Nothing comes after Fingerprint
					StunAttr::Fingerprint(f) => {
						fingerprint = Some((f, i));
						attrs.push(attr);
					}
					_ if integrity.is_some() => {} // The only attribute that can come after integrity is the fingerprint
					StunAttr::Integrity(buff) => {
						integrity = Some((buff, i));
						attrs.push(attr);
					}
					_ => attrs.push(attr),
				}
			}
		}

		// Check the fingerprint
		if let Some((f, length)) = fingerprint {
			let mut expected = crc32fast::Hasher::new();
			expected.update(&buffer[..2]);
			expected.update(&length.to_be_bytes());
			expected.update(&buffer[4..][..20 - 4 + length as usize - 8]);
			let expected = expected.finalize() ^ 0x5354554e;
			if f != expected {
				return Err(eyre!("STUN fingerprint check failed"));
			}
		}

		// Check the integrity
		if let Some((i, length)) = integrity {
			let (username, realm, password) = match auth {
				StunAuth::NoAuth => return Err(eyre!("STUN auth failure: packed included an integrity, but auth was NoAuth.")),
				StunAuth::Static { username, realm, password } => (username, realm, password),
				StunAuth::Get(f) => {
					let Some(username) = attrs.iter().find_map(|a| match a {
						StunAttr::Username(s) => Some(s.as_str()),
						_ => None
					}) else {
						return Err(eyre!("STUN auth failure: packet included an integrity, but didn't include a username."));
					};
					let realm = attrs.iter().find_map(|a| match a { StunAttr::Realm(s) => Some(s.as_str()), _ => None});
					let Some(password) = f(username, realm) else {
						return Err(eyre!("STUN auth failure: StunAuth::Get closure returned None password."));
					};
					(username, realm, password)
				}
			};

			let turn_auth;
			let key_data = match realm {
				Some(realm) => {
					turn_auth = mbedtls_util::md5(&[
						username.as_bytes(),
						":".as_bytes(),
						realm.as_bytes(),
						":".as_bytes(),
						password.as_bytes()
					]);
					&turn_auth
				},
				None => password.as_bytes()
			};

			let expected = mbedtls_util::sha1_hmac(key_data, &[
				&buffer[..2],
				&length.to_be_bytes(),
				&buffer[4..][..(20 - 4) + length as usize - 4 - 20]
			]);

			if expected != i {
				return Err(eyre!("Integrity Check failed."));
			}
		}

		Ok(Self {
			typ, txid, attrs: Cow::Owned(attrs)
		})
	}
	pub fn parse(buffer: &'i[u8]) -> Result<Self> {
		Self::parse_auth(buffer, StunAuth::NoAuth)
	}
	pub fn encode(&self, buff: &mut Vec<u8>) {
		let mut length = 0;
		for attr in self.attrs.iter() {
			length += 4;
			length += attr.length();
			while length % 4 != 0 { length += 1; }
		}
		buff.reserve(20 + length as usize);

		buff.extend_from_slice(&u16::from(self.typ).to_be_bytes());
		buff.extend_from_slice(&length.to_be_bytes());
		buff.extend_from_slice(&0x2112A442u32.to_be_bytes());
		buff.extend_from_slice(self.txid.as_ref());

		let mut xor_bytes = [0u8; 16];
		xor_bytes[..4].copy_from_slice(&0x2112A442u32.to_be_bytes());
		xor_bytes[4..].copy_from_slice(self.txid.as_ref());

		for attr in self.attrs.iter() {
			attr.encode(buff, &xor_bytes)
		}
	}
}
