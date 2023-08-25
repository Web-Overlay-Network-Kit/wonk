use attr::StunAttrDecodeErr;
use bytes::Buf;

pub mod attr;
pub mod attrs;
use attr::AttrContext;
use attr::StunAttr;
use attrs::flat::Flat;
use attrs::StunAttrs;

#[derive(Debug, Clone)]
pub enum StunDecodeErr {
	PacketTooSmall,
	TypeOutOfRange,
	UnalignedLength,
	BadMagic,
	AttrErr(StunAttrDecodeErr),
}

#[derive(Debug, Clone)]
pub enum StunTyp {
	Req(u16),
	Ind(u16),
	Res(u16),
	Err(u16),
}
impl StunTyp {
	pub fn method(&self) -> u16 {
		match self {
			Self::Req(m) => *m,
			Self::Ind(m) => *m,
			Self::Res(m) => *m,
			Self::Err(m) => *m,
		}
	}
}
impl TryFrom<u16> for StunTyp {
	type Error = StunDecodeErr;
	fn try_from(value: u16) -> Result<Self, StunDecodeErr> {
		if value >= 0x4000 {
			return Err(StunDecodeErr::TypeOutOfRange);
		}
		let method = ((value & 0b00_00000_0_000_0_1111) >> 0)
			| ((value & 0b00_00000_0_111_0_0000) >> 1)
			| ((value & 0b00_11111_0_000_0_0000) >> 2);
		Ok(match value & 0b00_00000_1_000_1_0000 {
			0b00_000000_0_000_0_0000 => Self::Req(method),
			0b00_000000_0_000_1_0000 => Self::Ind(method),
			0b00_000000_1_000_0_0000 => Self::Res(method),
			0b00_000000_1_000_1_0000 => Self::Err(method),
			_ => unreachable!(),
		})
	}
}
impl From<&StunTyp> for u16 {
	fn from(value: &StunTyp) -> Self {
		let (class, method) = match value {
			StunTyp::Req(m) => (0b00_000000_0_000_0_0000, m),
			StunTyp::Ind(m) => (0b00_000000_0_000_1_0000, m),
			StunTyp::Res(m) => (0b00_000000_1_000_0_0000, m),
			StunTyp::Err(m) => (0b00_000000_1_000_1_0000, m),
		};
		((method & 0b00_00000_0_000_0_1111) << 0)
			| ((method & 0b00_00000_0_111_0_0000) << 1)
			| ((method & 0b00_11111_0_000_0_0000) << 2)
			| class
	}
}

#[derive(Debug, Clone)]
pub struct Stun<'i> {
	pub typ: StunTyp,
	pub txid: [u8; 12],
	pub attrs: Vec<StunAttr<'i>>
}
impl<'i> Stun<'i> {
	pub fn flat(&self) -> Flat<'i> {
		Flat::from_iter(self)
	}
	pub fn length(&self) -> u16 {
		let mut ret = 0;
		for a in &self.attrs {
			ret += a.len();
		}
		ret
	}
	pub fn len(&self) -> usize {
		20 + self.length() as usize
	}
	pub fn res(&self, attrs: &'i [StunAttr<'i>]) -> Self {
		Self {
			typ: StunTyp::Res(self.typ.method()),
			txid: self.txid,
			attrs: attrs.into(),
		}
	}
	pub fn err(&self, attrs: &'i [StunAttr<'i>]) -> Self {
		Self {
			typ: StunTyp::Err(self.typ.method()),
			txid: self.txid,
			attrs: attrs.into(),
		}
	}
	pub fn decode(buff: &'i [u8]) -> Result<Self, StunDecodeErr> {
		let mut buf = buff;
		if buf.remaining() < 20 { return Err(StunDecodeErr::PacketTooSmall) }
		let typ = buf.get_u16();
		let typ = StunTyp::try_from(typ)?;

		let length = buf.get_u16();
		if length % 4 != 0 {
			return Err(StunDecodeErr::UnalignedLength);
		}

		let magic = buf.get_u32();
		if magic != 0x2112A442 {
			return Err(StunDecodeErr::BadMagic);
		}

		let mut txid = [0u8; 12];
		buf.copy_to_slice(&mut txid);

		if buf.remaining() < length as usize {
			return Err(StunDecodeErr::PacketTooSmall);
		}

		let mut attrs = Vec::new();

		for a in &(StunAttrs::Parse {
			buff: &buff[20..][..length as usize],
			header: (&buff[0..][..20]).try_into().unwrap(),
		}) {
			attrs.push(a.map_err(|e| StunDecodeErr::AttrErr(e))?);
		}

		Ok(Self { typ, txid, attrs })
	}
	pub fn encode(&self, buff: &mut [u8]) -> Option<usize> {
		let length = self.length();
		let len = 20 + length as usize;
		if buff.len() < len {
			return None;
		}
		buff[0..][..2].copy_from_slice(&u16::from(&self.typ).to_be_bytes());
		buff[2..][..2].copy_from_slice(&length.to_be_bytes());
		buff[4..][..4].copy_from_slice(&0x2112A442u32.to_be_bytes());
		buff[8..][..12].copy_from_slice(&self.txid);
		let (header, buff) = buff.split_at_mut(20);
		let header = <&[u8; 20]>::try_from(&*header).unwrap();

		let mut length = 0;
		let (mut attrs_prefix, mut to_write) = buff.split_at_mut(length);
		for attr in &self.attrs {
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

		Some(len)
	}
}

impl<'i, 'a> IntoIterator for &'a Stun<'i> {
	type Item = StunAttr<'i>;
	type IntoIter = StunIter<'i, 'a>;
	fn into_iter(self) -> Self::IntoIter {
		StunIter {
			integrity: false,
			fingerprint: false,
			attrs: self.attrs.iter(),
		}
	}
}
pub struct StunIter<'i, 'a> {
	integrity: bool,
	fingerprint: bool,
	attrs: std::slice::Iter<'a, StunAttr<'i>>
}
impl<'i, 'a> Iterator for StunIter<'i, 'a> {
	type Item = StunAttr<'i>;
	fn next(&mut self) -> Option<Self::Item> {
		let attr = self.attrs.next()?;
		match attr {
			_ if self.fingerprint => return None,
			StunAttr::Fingerprint => self.fingerprint = true,
			_ if self.integrity => return None,
			StunAttr::Integrity(_) => self.integrity = true,
			_ => {}
		}
		Some(attr.clone())
	}
}
