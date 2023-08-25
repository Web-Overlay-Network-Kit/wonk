use std::{
	array::TryFromSliceError,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::Utf8Error,
};
use super::Stun;

use hmac::Mac;
use sha1::Sha1;

#[derive(Debug, Clone)]
pub enum StunAttrDecodeErr {
	AttrLengthExceedsPacketLength,
	ValueUnexpectedLength,
	BadUtf8(Utf8Error),
	UnexpectedLength(TryFromSliceError),
	BadFingerprint,
}
impl From<Utf8Error> for StunAttrDecodeErr {
	fn from(value: Utf8Error) -> Self {
		Self::BadUtf8(value)
	}
}
impl From<TryFromSliceError> for StunAttrDecodeErr {
	fn from(value: TryFromSliceError) -> Self {
		Self::UnexpectedLength(value)
	}
}

#[derive(Debug, Clone)]
pub struct AttrContext<'i> {
	pub header: &'i [u8; 20],
	pub zero_xor_bytes: bool, // TODO: Is this ok?
	pub attrs_prefix: &'i [u8],
	pub attr_len: u16,
}
impl<'i> AttrContext<'i> {
	// Used by xor encoded addresses:
	pub fn xor_bytes(&self) -> &'i [u8; 16] {
		if self.zero_xor_bytes {
			&[0u8; 16]
		} else {
			self.header[4..][..16].try_into().unwrap()
		}
	}
	// Used by Integrity and Fingerprint attributes:
	pub fn reduce_over_prefix<F: FnMut(&[u8])>(&self, mut func: F) {
		func(&self.header[..2]); // STUN Type
		func(&(self.attrs_prefix.len() as u16 + self.attr_len).to_be_bytes()); // Simulated STUN length
		func(&self.header[4..]); // Rest of the STUN header (equivalent to xor_bytes)
		func(self.attrs_prefix); // All of the written attributes up-to but not including the current attribute
	}
}

pub trait StunAttrValue<'i> {
	fn length(&self) -> u16;
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>);
	fn decode(buff: &'i [u8], ctx: AttrContext<'i>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized;
}

// This might not be exactly the same as IpAddr::to_canonical, but whatevs
fn to_canonical(ip: IpAddr) -> IpAddr {
	if let IpAddr::V6(v6) = ip {
		if let Some(v4) = v6.to_ipv4_mapped() {
			return IpAddr::V4(v4);
		}
	}
	ip
}
impl StunAttrValue<'_> for SocketAddr {
	fn length(&self) -> u16 {
		match to_canonical(self.ip()) {
			IpAddr::V4(_) => 8,
			IpAddr::V6(_) => 20,
		}
	}
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		let xor_bytes = ctx.xor_bytes();
		buff[0] = 0;
		let ip = to_canonical(self.ip());
		let family = match ip {
			IpAddr::V4(_) => 0x01,
			IpAddr::V6(_) => 0x02,
		};
		buff[1] = family;
		let port = self.port().to_be_bytes();
		let xport: [u8; 2] = std::array::from_fn(|i| port[i] ^ xor_bytes[i]);
		buff[2..][..2].copy_from_slice(&xport);
		match ip {
			IpAddr::V4(ip) => {
				let octs = ip.octets();
				let xocts: [u8; 4] = std::array::from_fn(|i| octs[i] ^ xor_bytes[i]);
				buff[4..][..4].copy_from_slice(&xocts)
			}
			IpAddr::V6(ip) => {
				let octs = ip.octets();
				let xocts: [u8; 16] = std::array::from_fn(|i| octs[i] ^ xor_bytes[i]);
				buff[4..][..16].copy_from_slice(&xocts);
			}
		}
	}
	fn decode(buff: &[u8], ctx: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		let xor_bytes = ctx.xor_bytes();
		if buff.len() < 8 {
			return Err(StunAttrDecodeErr::ValueUnexpectedLength);
		}

		let family = buff[1];
		let xport = &buff[2..][..2];
		let port = u16::from_be_bytes(std::array::from_fn(|i| xport[i] ^ xor_bytes[i]));

		let xip = &buff[4..];
		let ip = match (family, xip.len()) {
			(0x01, 4) => Ipv4Addr::from(std::array::from_fn(|i| xip[i] ^ xor_bytes[i])).into(),
			(0x02, 16) => Ipv6Addr::from(std::array::from_fn(|i| xip[i] ^ xor_bytes[i])).into(),
			_ => return Err(StunAttrDecodeErr::ValueUnexpectedLength),
		};
		Ok(SocketAddr::new(ip, port))
	}
}
impl StunAttrValue<'_> for () {
	fn length(&self) -> u16 {
		0
	}
	fn encode(&self, _: &mut [u8], _: AttrContext<'_>) {}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		if buff.len() == 0 {
			Ok(())
		} else {
			Err(StunAttrDecodeErr::ValueUnexpectedLength)
		}
	}
}
impl<'i> StunAttrValue<'i> for &'i str {
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff.copy_from_slice(self.as_bytes())
	}
	fn decode(buff: &'i [u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		Ok(std::str::from_utf8(buff)?)
	}
}
impl<'i> StunAttrValue<'i> for &'i [u8] {
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff.copy_from_slice(self)
	}
	fn decode(buff: &'i [u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		Ok(buff)
	}
}
impl<'i, const N: usize> StunAttrValue<'i> for &'i [u8; N] {
	fn length(&self) -> u16 {
		N as u16
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff.copy_from_slice(self.as_slice())
	}
	fn decode(buff: &'i [u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		Ok(buff.try_into()?)
	}
}
impl StunAttrValue<'_> for u32 {
	fn length(&self) -> u16 {
		self.to_be_bytes().len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff.copy_from_slice(&self.to_be_bytes())
	}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		Ok(Self::from_be_bytes(buff.try_into()?))
	}
}
impl StunAttrValue<'_> for u64 {
	fn length(&self) -> u16 {
		self.to_be_bytes().len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff.copy_from_slice(&self.to_be_bytes())
	}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		Ok(Self::from_be_bytes(buff.try_into()?))
	}
}
#[derive(Debug, Clone)]
pub struct Error<'i> {
	pub code: u16,
	pub message: &'i str,
}
impl<'i> StunAttrValue<'i> for Error<'i> {
	fn length(&self) -> u16 {
		4 + self.message.len() as u16
	}
	fn decode(buff: &'i [u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		if buff.len() < 4 {
			return Err(StunAttrDecodeErr::ValueUnexpectedLength);
		}

		let code = (buff[2] as u16 * 100) + buff[3] as u16;
		let message = std::str::from_utf8(&buff[4..])?;
		Ok(Self { code, message })
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff[0] = 0;
		buff[1] = 0;
		buff[2] = (self.code / 100) as u8;
		buff[3] = (self.code % 100) as u8;
		buff[4..].copy_from_slice(self.message.as_bytes());
	}
}

#[derive(Debug, Clone)]
pub enum UnknownAttributes<'i> {
	Parse(&'i [u8]),
	List(&'i [u16]),
}
impl<'i> StunAttrValue<'i> for UnknownAttributes<'i> {
	fn length(&self) -> u16 {
		match self {
			Self::Parse(s) => s.len() as u16,
			Self::List(l) => (l.len() * 2) as u16,
		}
	}
	fn encode(&self, mut buff: &mut [u8], _: AttrContext<'_>) {
		match self {
			Self::Parse(s) => buff.copy_from_slice(s),
			Self::List(l) => {
				for n in l.iter() {
					buff[..2].copy_from_slice(&n.to_be_bytes());
					buff = &mut buff[2..];
				}
			}
		}
	}
	fn decode(buff: &'i [u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		if buff.len() % 2 != 0 {
			Err(StunAttrDecodeErr::ValueUnexpectedLength)
		} else {
			Ok(Self::Parse(buff))
		}
	}
}
#[derive(Debug, Clone)]
pub struct EvenPort(pub bool);
impl StunAttrValue<'_> for EvenPort {
	fn length(&self) -> u16 {
		1
	}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		if buff.len() != 1 {
			return Err(StunAttrDecodeErr::ValueUnexpectedLength);
		}
		Ok(Self(buff[0] & 0b1_0000000 != 0))
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff[0] = match self.0 {
			true => 0b1_0000000,
			false => 0,
		};
	}
}
#[derive(Debug, Clone)]
pub struct RequestedTransport(pub u8);
impl StunAttrValue<'_> for RequestedTransport {
	fn length(&self) -> u16 {
		4
	}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		if buff.len() != 4 {
			return Err(StunAttrDecodeErr::ValueUnexpectedLength);
		}
		Ok(Self(buff[0]))
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff[0] = self.0;
		buff[1] = 0;
		buff[2] = 0;
		buff[3] = 0;
	}
}
#[derive(Debug, Clone)]
pub struct ZeroXor<V>(pub V);
impl<'i, V: StunAttrValue<'i>> StunAttrValue<'i> for ZeroXor<V> {
	fn length(&self) -> u16 {
		self.0.length()
	}
	fn decode(buff: &'i [u8], ctx: AttrContext<'i>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		let ctx = AttrContext {
			zero_xor_bytes: true,
			..ctx
		};
		V::decode(buff, ctx).map(|v| Self(v))
	}
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		let ctx = AttrContext {
			zero_xor_bytes: true,
			..ctx
		};
		self.0.encode(buff, ctx)
	}
}
impl<V> ZeroXor<V> {
	pub fn into(self) -> V {
		self.0
	}
}
impl<V> From<V> for ZeroXor<V> {
	fn from(value: V) -> Self {
		Self(value)
	}
}
#[derive(Debug, Clone)]
pub struct Fingerprint;
impl StunAttrValue<'_> for Fingerprint {
	fn length(&self) -> u16 {
		0u32.length()
	}
	fn decode(buff: &'_ [u8], ctx: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		let actual = u32::decode(buff, ctx.clone())?;
		let mut hasher = crc32fast::Hasher::new();
		ctx.reduce_over_prefix(|buf| hasher.update(buf));
		let expected = hasher.finalize() ^ 0x5354554e;
		if expected == actual {
			Ok(Self)
		} else {
			Err(StunAttrDecodeErr::BadFingerprint)
		}
	}
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		let mut hasher = crc32fast::Hasher::new();
		ctx.reduce_over_prefix(|buf| hasher.update(buf));
		let actual = hasher.finalize() ^ 0x5354554e;
		actual.encode(buff, ctx)
	}
}
#[derive(Debug, Clone)]
pub enum Integrity<'i> {
	Check {
		val: &'i [u8; 20],
		ctx: AttrContext<'i>,
	},
	Set {
		key_data: &'i [u8],
	},
}
impl<'i> Integrity<'i> {
	pub fn verify(&self, key_data: &[u8]) -> bool {
		match self {
			Self::Set {
				key_data: actual_key_data,
			} => key_data == *actual_key_data,
			Self::Check { val: actual, ctx } => {
				let mut hmac = hmac::Hmac::<Sha1>::new_from_slice(key_data).expect("bad key_data");
				ctx.reduce_over_prefix(|buf| hmac.update(buf));
				let expected = hmac.finalize().into_bytes();
				expected.as_slice() == actual.as_slice()
			}
		}
	}
}
impl<'i> StunAttrValue<'i> for Integrity<'i> {
	fn length(&self) -> u16 {
		20
	}
	fn decode(buff: &'i [u8], ctx: AttrContext<'i>) -> Result<Self, StunAttrDecodeErr>
	where
		Self: Sized,
	{
		let val = <&[u8; 20]>::decode(buff, ctx.clone())?;
		Ok(Self::Check { val, ctx })
	}
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		match self {
			Self::Check { val, .. } => val.encode(buff, ctx),
			Self::Set { key_data } => {
				let mut hmac = hmac::Hmac::<Sha1>::new_from_slice(key_data)
					.expect("Unable to create Hmac key");
				ctx.reduce_over_prefix(|buf| hmac.update(buf));
				let actual = hmac.finalize().into_bytes();
				<&[u8; 20]>::try_from(actual.as_slice())
					.unwrap()
					.encode(buff, ctx);
			}
		}
	}
}
#[derive(Debug, Clone)]
pub enum Data<'i> {
	Slice(&'i [u8]),
	Nested(Stun<'i>)
}
impl<'i> StunAttrValue<'i> for Data<'i> {
	fn length(&self) -> u16 {
		match self {
			Self::Slice(s) => s.len() as u16,
			Self::Nested(m) => m.len() as u16
		}
	}
	fn decode(buff: &'i [u8], ctx: AttrContext<'i>) -> Result<Self, StunAttrDecodeErr> {
		let s = <&[u8]>::decode(buff, ctx)?;
		Ok(Self::Slice(s))
	}
	fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		match self {
			Self::Slice(s) => s.encode(buff, ctx),
			Self::Nested(m) => { m.encode(buff); }
		}
	}
}
#[derive(Debug, Clone)]
pub struct Channel(u16);
impl StunAttrValue<'_> for Channel {
	fn length(&self) -> u16 {
		4
	}
	fn decode(buff: &[u8], _: AttrContext<'_>) -> Result<Self, StunAttrDecodeErr> {
		if buff.len() != 4 { return Err(StunAttrDecodeErr::ValueUnexpectedLength) }
		Ok(Self(u16::from_be_bytes(buff[..2].try_into().unwrap())))
	}
	fn encode(&self, buff: &mut [u8], _: AttrContext<'_>) {
		buff[..2].copy_from_slice(&self.0.to_be_bytes());
		buff[2] = 0;
		buff[3] = 0;
	}
}
impl From<u16> for Channel {
	fn from(value: u16) -> Self {
		Self(value)
	}
}
impl From<Channel> for u16 {
	fn from(value: Channel) -> Self {
		value.0
	}
}


#[derive(Debug, Clone)]
pub enum StunAttr<'i> {
	// RFC 5389:
	/* 0x0001 */ Mapped(ZeroXor<SocketAddr>),
	/* 0x0006 */ Username(&'i str),
	/* 0x0008 */ Integrity(Integrity<'i>),
	/* 0x0009 */ Error(Error<'i>),
	/* 0x000A */ UnknownAttributes(UnknownAttributes<'i>),
	/* 0x0014 */ Realm(&'i str),
	/* 0x0015 */ Nonce(&'i str),
	/* 0x0020 */ XMapped(SocketAddr),
	/* 0x8022 */ Software(&'i str),
	/* 0x8023 */ AlternateServer(ZeroXor<SocketAddr>),
	/* 0x8028 */ Fingerprint,

	// RFC 5766:
	/* 0x000C */ Channel(Channel),
	/* 0x000D */ Lifetime(u32),
	/* 0x0012 */ XPeer(SocketAddr),
	/* 0x0013 */ Data(Data<'i>),
	/* 0x0016 */ XRelayed(SocketAddr),
	/* 0x0018 */ EvenPort(EvenPort),
	/* 0x0019 */ RequestedTransport(RequestedTransport),
	/* 0x001A */ DontFragment,
	/* 0x0022 */ ReservationToken(u32),

	// RFC 5245 / 8445:
	/* 0x0024 */ Priority(u32),
	/* 0x0025 */ UseCandidate,
	/* 0x8029 */ IceControlled(u64),
	/* 0x802A */ IceControlling(u64),

	Other(u16, &'i [u8]),
}
impl<'i> StunAttr<'i> {
	pub fn typ(&self) -> u16 {
		match self {
			Self::Mapped(_) => 0x0001,
			Self::Username(_) => 0x0006,
			Self::Integrity(_) => 0x0008,
			Self::Error(_) => 0x0009,
			Self::UnknownAttributes(_) => 0x000A,
			Self::Realm(_) => 0x0014,
			Self::Nonce(_) => 0x0015,
			Self::XMapped(_) => 0x0020,
			Self::Software(_) => 0x8022,
			Self::AlternateServer(_) => 0x8023,
			Self::Fingerprint => 0x8028,
			Self::Channel(_) => 0x000C,
			Self::Lifetime(_) => 0x000D,
			Self::XPeer(_) => 0x0012,
			Self::Data(_) => 0x0013,
			Self::XRelayed(_) => 0x0016,
			Self::EvenPort(_) => 0x0018,
			Self::RequestedTransport(_) => 0x0019,
			Self::DontFragment => 0x001A,
			Self::ReservationToken(_) => 0x0022,
			Self::Priority(_) => 0x0024,
			Self::UseCandidate => 0x0025,
			Self::IceControlled(_) => 0x8029,
			Self::IceControlling(_) => 0x802A,
			Self::Other(typ, _) => *typ,
		}
	}
	pub fn value(&self) -> &dyn StunAttrValue<'i> {
		match self {
			Self::DontFragment | Self::UseCandidate => &(),
			Self::Mapped(v) => v,
			Self::Username(v) => v,
			Self::Integrity(v) => v,
			Self::Error(v) => v,
			Self::UnknownAttributes(v) => v,
			Self::Realm(v) => v,
			Self::Nonce(v) => v,
			Self::XMapped(v) => v,
			Self::Software(v) => v,
			Self::AlternateServer(v) => v,
			Self::Fingerprint => &Fingerprint,
			Self::Channel(v) => v,
			Self::Lifetime(v) => v,
			Self::XPeer(v) => v,
			Self::Data(v) => v,
			Self::XRelayed(v) => v,
			Self::EvenPort(v) => v,
			Self::RequestedTransport(v) => v,
			Self::ReservationToken(v) => v,
			Self::Priority(v) => v,
			Self::IceControlled(v) => v,
			Self::IceControlling(v) => v,
			Self::Other(_, v) => v,
		}
	}
	pub fn length(&self) -> u16 {
		self.value().length()
	}
	pub fn len(&self) -> u16 {
		let mut ret = 4 + self.length();
		while ret % 4 != 0 {
			ret += 1;
		}
		ret
	}
	pub fn encode(&self, buff: &mut [u8], ctx: AttrContext<'_>) {
		buff[0..][..2].copy_from_slice(&self.typ().to_be_bytes());
		buff[2..][..2].copy_from_slice(&self.length().to_be_bytes());
		let mut length = self.length();
		self.value().encode(&mut buff[4..][..length as usize], ctx);
		while length % 4 != 0 {
			buff[4 + length as usize] = 0;
			length += 1;
		}
	}
	pub fn decode(
		typ: u16,
		buff: &'i [u8],
		ctx: AttrContext<'i>,
	) -> Result<Self, StunAttrDecodeErr> {
		Ok(match typ {
			0x0001 => Self::Mapped(StunAttrValue::decode(buff, ctx)?),
			0x0006 => Self::Username(StunAttrValue::decode(buff, ctx)?),
			0x0008 => Self::Integrity(StunAttrValue::decode(buff, ctx)?),
			0x0009 => Self::Error(StunAttrValue::decode(buff, ctx)?),
			0x000A => Self::UnknownAttributes(StunAttrValue::decode(buff, ctx)?),
			0x0014 => Self::Realm(StunAttrValue::decode(buff, ctx)?),
			0x0015 => Self::Nonce(StunAttrValue::decode(buff, ctx)?),
			0x0020 => Self::XMapped(StunAttrValue::decode(buff, ctx)?),
			0x8022 => Self::Software(StunAttrValue::decode(buff, ctx)?),
			0x8023 => Self::AlternateServer(StunAttrValue::decode(buff, ctx)?),
			0x8028 => {
				Fingerprint::decode(buff, ctx)?;
				Self::Fingerprint
			}
			0x000C => Self::Channel(StunAttrValue::decode(buff, ctx)?),
			0x000D => Self::Lifetime(StunAttrValue::decode(buff, ctx)?),
			0x0012 => Self::XPeer(StunAttrValue::decode(buff, ctx)?),
			0x0013 => Self::Data(StunAttrValue::decode(buff, ctx)?),
			0x0016 => Self::XRelayed(StunAttrValue::decode(buff, ctx)?),
			0x0018 => Self::EvenPort(StunAttrValue::decode(buff, ctx)?),
			0x0019 => Self::RequestedTransport(StunAttrValue::decode(buff, ctx)?),
			0x001A => {
				<()>::decode(buff, ctx.clone())?;
				Self::DontFragment
			}
			0x0022 => Self::ReservationToken(StunAttrValue::decode(buff, ctx)?),
			0x0024 => Self::Priority(StunAttrValue::decode(buff, ctx)?),
			0x0025 => {
				<()>::decode(buff, ctx.clone())?;
				Self::UseCandidate
			}
			0x8029 => Self::IceControlled(StunAttrValue::decode(buff, ctx)?),
			0x802A => Self::IceControlling(StunAttrValue::decode(buff, ctx)?),
			typ => Self::Other(typ, buff),
		})
	}
}
