use eyre::{Result, eyre};
use crate::attr::StunAttr;

#[derive(Debug, Clone)]
pub enum StunAttrs<'i> {
	Parse {
		buff: &'i [u8],
		xor_bytes: &'i [u8; 16]
	},
	List(&'i [StunAttr<'i>])
}
impl<'i> StunAttrs<'i> {
	pub fn len(&self) -> u16 {
		match self {
			Self::Parse { buff, .. } => buff.len() as u16,
			Self::List(l) => {
				let mut ret = 0;
				for attr in l.iter() {
					ret += attr.len();
				}
				ret
			}
		}
	}
	pub fn encode(&self, mut buff: &mut [u8], xor_bytes: &[u8; 16]) {
		match self {
			Self::Parse { buff: parse, ..} => buff.copy_from_slice(parse),
			Self::List(l) => for attr in l.iter() {
				attr.encode(buff, xor_bytes);

				buff = &mut buff[attr.len() as usize..];
			}
		}
	}
}
impl<'i, 'a> IntoIterator for &'a StunAttrs<'i> {
	type Item = Result<StunAttr<'i>>;
	type IntoIter = StunAttrsIter<'i, 'a>;
	fn into_iter(self) -> Self::IntoIter {
		match self {
			StunAttrs::Parse { buff, xor_bytes } => StunAttrsIter::Parse { buff, xor_bytes },
			StunAttrs::List(l) => StunAttrsIter::List(l.into_iter())
		}
	}
}
impl<'i> From<&'i [StunAttr<'i>]> for StunAttrs<'i> {
	fn from(value: &'i [StunAttr<'i>]) -> Self {
		Self::List(value)
	}
}

pub enum StunAttrsIter<'i, 'a> {
	Parse {
		buff: &'i [u8],
		xor_bytes: &'i [u8; 16]
	},
	List(std::slice::Iter<'a, StunAttr<'i>>)
}
impl<'i, 'a> Iterator for StunAttrsIter<'i, 'a> {
	type Item = Result<StunAttr<'i>>;
	fn next(&mut self) -> Option<Self::Item> {
		match self {
			Self::List(i) => i.next().map(|a| Ok(a.clone())),
			Self::Parse { buff, xor_bytes } => {
				if buff.len() < 4 { return None; }
				let typ = u16::from_be_bytes(buff[0..][..2].try_into().unwrap());
				let len = u16::from_be_bytes(buff[2..][..2].try_into().unwrap());
				let ret = Some(if buff.len() - 4 < len as usize {
					Err(eyre!("STUN attribute is too big"))
				} else {
					let data = &buff[4..][..len as usize];
					StunAttr::parse(typ, data, *xor_bytes)
				});
				let mut padded_len = len;
				while padded_len % 4 != 0 { padded_len += 1; }
				*buff = &buff[(4 + padded_len as usize)..];
				ret
			}
		}
	}
}
