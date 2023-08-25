use crate::attr::{AttrContext, StunAttr, StunAttrDecodeErr};

pub mod flat;

#[derive(Debug, Clone)]
pub enum StunAttrs<'i> {
	Parse {
		buff: &'i [u8],
		header: &'i [u8; 20],
	},
	List(&'i [StunAttr<'i>]),
	// Flat(&'i StunAttrsFlat<'i>) // TODO: Add?
}
impl<'i> StunAttrs<'i> {
	pub fn length(&self) -> u16 {
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
	pub fn encode(&self, buff: &mut [u8], header: &[u8; 20]) {
		match self {
			Self::Parse { buff: parse, .. } => buff.copy_from_slice(parse),
			Self::List(l) => {
				let mut length = 0;
				let (mut attrs_prefix, mut to_write) = buff.split_at_mut(length);
				for attr in l.iter() {
					let attr_len = attr.len();
					let ctx = AttrContext {
						header,
						attrs_prefix,
						attr_len,
						zero_xor_bytes: false,
					};
					attr.encode(&mut to_write[..attr_len as usize], ctx);

					length += attr.len() as usize;
					(attrs_prefix, to_write) = buff.split_at_mut(length);
				}
			}
		}
	}
}
impl<'i, 'a> IntoIterator for &'a StunAttrs<'i> {
	type Item = Result<StunAttr<'i>, StunAttrDecodeErr>;
	type IntoIter = StunAttrsIter<'i, 'a>;
	fn into_iter(self) -> Self::IntoIter {
		match self {
			StunAttrs::Parse { buff, header } => StunAttrsIter::Parse {
				buff,
				header,
				length: 0,
			},
			StunAttrs::List(l) => StunAttrsIter::List(l.into_iter()),
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
		header: &'i [u8; 20],
		buff: &'i [u8],
		length: usize,
	},
	List(std::slice::Iter<'a, StunAttr<'i>>),
}
impl<'i, 'a> Iterator for StunAttrsIter<'i, 'a> {
	type Item = Result<StunAttr<'i>, StunAttrDecodeErr>;
	fn next(&mut self) -> Option<Self::Item> {
		match self {
			Self::List(i) => i.next().map(|a| Ok(a.clone())),
			Self::Parse {
				buff,
				header,
				length,
			} => {
				let (attrs_prefix, unread) = buff.split_at(*length);
				if unread.len() < 4 {
					return None;
				}
				let typ = u16::from_be_bytes(unread[0..][..2].try_into().unwrap());
				let attr_length = u16::from_be_bytes(unread[2..][..2].try_into().unwrap());
				let attr_len = 4 + attr_length;
				let ret = Some(if unread.len() < attr_len as usize {
					Err(StunAttrDecodeErr::AttrLengthExceedsPacketLength)
				} else {
					let ctx = AttrContext {
						header,
						attrs_prefix,
						attr_len,
						zero_xor_bytes: false,
					};
					let data = &unread[4..][..attr_length as usize];
					StunAttr::decode(typ, data, ctx)
				});

				let mut padded_len = attr_len;
				while padded_len % 4 != 0 {
					padded_len += 1;
				}
				*length = *length + padded_len as usize;

				ret
			}
		}
	}
}
