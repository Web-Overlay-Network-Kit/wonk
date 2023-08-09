use eyre::{Result, eyre, Report};
use std::net::{SocketAddr, IpAddr};

#[derive(Debug, Clone)]
pub enum UnknownAttributes<'i> {
	Parse(&'i [u8]),
	List(&'i [u16])
}
impl<'i> UnknownAttributes<'i> {
	pub fn len(&self) -> u16 {
		match self {
			Self::Parse(s) => s.len() as u16,
			Self::List(l) => (l.len() * 2) as u16
		}
	}
	pub fn encode(&self, mut buff: &mut [u8]) {
		match self {
			Self::Parse(s) => buff.copy_from_slice(s),
			Self::List(l) => for t in l.as_ref() {
				buff[..2].copy_from_slice(&t.to_be_bytes());
				buff = &mut buff[2..];
			}
		}
	}
}
impl<'i> TryFrom<&'i [u8]> for UnknownAttributes<'i> {
	type Error = Report;
	fn try_from(value: &'i [u8]) -> Result<Self> {
		if value.len() % 2 != 0 { return Err(eyre!("UnknownAttributes slice not 2-byte aligned.")); }
		Ok(UnknownAttributes::Parse(value))
	}
}
impl<'i> IntoIterator for &'i UnknownAttributes<'i> {
	type Item = u16;
	type IntoIter = UnknownAttributesIter<'i>;
	fn into_iter(self) -> Self::IntoIter {
		match self {
			UnknownAttributes::Parse(s) => UnknownAttributesIter::Parse(s),
			UnknownAttributes::List(l) => UnknownAttributesIter::List(l.into_iter())
		}
	}
}

pub enum UnknownAttributesIter<'i> {
	Parse(&'i [u8]),
	List(std::slice::Iter<'i, u16>)
}
impl<'a> Iterator for UnknownAttributesIter<'a> {
	type Item = u16;
	fn next(&mut self) -> Option<Self::Item> {
		match self {
			Self::Parse(s) => {
				if s.len() < 2 { return None; }
				let ret = u16::from_be_bytes(s[..2].try_into().unwrap());
				*s = &s[2..];
				Some(ret)
			},
			Self::List(i) => i.next().cloned()
		}
	}
}

#[derive(Debug, Clone)]
pub enum StunAttr<'i> {
	// RFC 5389:
	/* 0x0001 */ Mapped(SocketAddr),
	/* 0x0006 */ Username(&'i str),
	/* 0x0008 */ Integrity(&'i [u8; 20]),
	/* 0x0009 */ Error { code: u16, message: &'i str },
	/* 0x000A */ UnknownAttributes(UnknownAttributes<'i>),
	/* 0x0014 */ Realm(&'i str),
	/* 0x0015 */ Nonce(&'i str),
	/* 0x0020 */ XMapped(SocketAddr),
	/* 0x8022 */ Software(&'i str),
	/* 0x8023 */ AlternateServer(SocketAddr),
	/* 0x8028 */ Fingerprint(u32),

	// RFC 5766:
	/* 0x000C */ Channel(u32),
	/* 0x000D */ Lifetime(u32),
	/* 0x0012 */ XPeer(SocketAddr),
	/* 0x0013 */ Data(&'i [u8]),
	/* 0x0016 */ XRelayed(SocketAddr),
	/* 0x0018 */ EvenPort(bool),
	/* 0x0019 */ RequestedTransport(u8),
	/* 0x001A */ DontFragment,
	/* 0x0022 */ ReservationToken(u32),

	// RFC 5245 / 8445:
	/* 0x0024 */ Priority(u32),
	/* 0x0025 */ UseCandidate,
	/* 0x8029 */ IceControlled(u64),
	/* 0x802A */ IceControlling(u64),

	Other(u16, &'i [u8])
}

fn map_xor_bytes<const N: usize>(mut arr: [u8; N], xor_bytes: &[u8; 16]) -> [u8; N] {
	for i in 0..N {
		arr[i] ^= xor_bytes[i]
	}
	arr
}

fn stun_addr_attr(data: &[u8], xor_bytes: &[u8; 16]) -> Result<SocketAddr> {
	if data.len() < 4 { return Err(eyre!("STUN Address type attribute is too short ({}).", data.len())); }
	let family = data[1];
	let port = u16::from_be_bytes(map_xor_bytes(data[2..][..2].try_into().unwrap(), xor_bytes));
	let ip = match family {
		0x01 => {
			if data.len() != 8 { return Err(eyre!("STUN Address type attribute is wrong size ({}) for family ({family}).", data.len())); }
			IpAddr::from(map_xor_bytes(<[u8; 4]>::try_from(&data[4..]).unwrap(), xor_bytes))
		},
		0x02 => {
			if data.len() != 20 { return Err(eyre!("STUN Address type attribute is wrong size ({}) for family ({family}).", data.len())); }
			IpAddr::from(map_xor_bytes(<[u8; 16]>::try_from(&data[4..]).unwrap(), xor_bytes))
		},
		_ => { return Err(eyre!("STUN Address attribute unknown family ({family}).")); }
	};
	Ok(SocketAddr::new(ip, port))
}

fn encode_addr_attr(addr: &SocketAddr, buff: &mut [u8], xor_bytes: &[u8; 16]) {
	let ip = addr.ip().to_canonical();
	buff[0] = 0;
	let family = if ip.is_ipv4() { 0x01 } else { 0x02 };
	buff[1] = family;
	buff[2..][..2].copy_from_slice(&map_xor_bytes(addr.port().to_be_bytes(), xor_bytes));
	match ip {
		IpAddr::V4(ip) => buff[4..][..4].copy_from_slice(&map_xor_bytes(ip.octets(), xor_bytes)),
		IpAddr::V6(ip) => buff[4..][..16].copy_from_slice(&map_xor_bytes(ip.octets(), xor_bytes))
	}
}


impl<'i> StunAttr<'i> {
	pub fn typ(&self) -> u16 {
		match self {
			Self::Mapped(_) => 0x0001,
			Self::Username(_) => 0x0006,
			Self::Integrity(_) => 0x0008,
			Self::Error{..} => 0x0009,
			Self::UnknownAttributes(_) => 0x000A,
			Self::Realm(_) => 0x0014,
			Self::Nonce(_) => 0x0015,
			Self::XMapped(_) => 0x0020,
			Self::Software(_) => 0x8022,
			Self::AlternateServer(_) => 0x8023,
			Self::Fingerprint(_) => 0x8028,

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
			
			Self::Other(typ, _) => *typ
		}
	}
	pub fn length(&self) -> u16 {
		match self {
			Self::Mapped(s) | Self::XMapped(s) |
			Self::AlternateServer(s) | Self::XPeer(s) |
			Self::XRelayed(s) => match s.ip().to_canonical() {
				IpAddr::V4(_) => 8,
				IpAddr::V6(_) => 20
			},
			Self::Username(s) | Self::Realm(s) |
			Self::Nonce(s) | Self::Software(s) => s.len() as u16,
			Self::Integrity(_) => 20,
			Self::Error{message, ..} => 4 + message.len() as u16,
			Self::UnknownAttributes(ua) => ua.len(),
			Self::Fingerprint(_) | Self::Channel(_) | Self::Lifetime(_) |
			Self::ReservationToken(_) | Self::Priority(_) => 4,
			Self::Data(v) => v.len() as u16,
			Self::EvenPort(_) => 1,
			Self::RequestedTransport(_) => 4,
			Self::DontFragment | Self::UseCandidate => 0,
			Self::IceControlled(_) | Self::IceControlling(_) => 8,
			Self::Other(_, v) => v.len() as u16
		}
	}
	pub fn len(&self) -> u16 {
		let mut ret = 4 + self.length();
		while ret % 4 != 0 { ret += 1; }
		ret
	}
	pub fn parse(typ: u16, data: &'i[u8], xor_bytes: &'_[u8; 16]) -> Result<Self> {
		Ok(match typ {
			0x0001 => Self::Mapped(stun_addr_attr(data, &[0; 16])?),
			0x0006 => Self::Username(std::str::from_utf8(data)?.into()),
			0x0008 => Self::Integrity(<&[u8; 20]>::try_from(data)?),
			0x0009 => {
				if data.len() < 4 { return Err(eyre!("Error attribute not long enough.")) }
				let code = 100 * data[2] as u16 + data[3] as u16;
				let message = std::str::from_utf8(&data[4..])?.into();
				Self::Error { code, message }
			},
			0x000A => Self::UnknownAttributes(data.try_into()?),
			0x0014 => Self::Realm(std::str::from_utf8(data)?.into()),
			0x0015 => Self::Nonce(std::str::from_utf8(data)?.into()),
			0x0020 => Self::XMapped(stun_addr_attr(data, xor_bytes)?),
			0x8022 => Self::Software(std::str::from_utf8(data)?.into()),
			0x8023 => Self::AlternateServer(stun_addr_attr(data, &[0; 16])?),
			0x8028 => Self::Fingerprint(u32::from_be_bytes(data.try_into()?)),

			0x000C => Self::Channel(u32::from_be_bytes(data.try_into()?)),
			0x000D => Self::Lifetime(u32::from_be_bytes(data.try_into()?)),
			0x0012 => Self::XPeer(stun_addr_attr(data, xor_bytes)?),
			0x0013 => Self::Data(data.into()),
			0x0016 => Self::XRelayed(stun_addr_attr(data, xor_bytes)?),
			0x0018 => Self::EvenPort(data.get(0).map(|b| b & 0b10000000 != 0).unwrap_or(true)),
			0x0019 => Self::RequestedTransport(data.get(0).cloned().ok_or(eyre!("STUN Requested Transport attribute wrong size."))?),
			0x001A => Self::DontFragment,
			0x0022 => Self::ReservationToken(u32::from_be_bytes(data.try_into()?)),

			0x0024 => Self::Priority(u32::from_be_bytes(data.try_into()?)),
			0x0025 => Self::UseCandidate,
			0x8029 => Self::IceControlled(u64::from_be_bytes(data.try_into()?)),
			0x802A => Self::IceControlling(u64::from_be_bytes(data.try_into()?)),

			_ => Self::Other(typ, data.into())
		})
	}
	pub fn encode(&self, buff: &mut [u8], xor_bytes: &[u8; 16]) {
		buff[0..][..2].copy_from_slice(&self.typ().to_be_bytes());
		let mut length = self.length();
		buff[2..][..2].copy_from_slice(&length.to_be_bytes());

		let data = &mut buff[4..][..length as usize];
		match self {
			Self::Mapped(s) | Self::AlternateServer(s) => encode_addr_attr(s, data, &[0; 16]),
			Self::XMapped(s) | Self::XPeer(s) | Self::XRelayed(s) => encode_addr_attr(s, data, xor_bytes),
			Self::Username(s) | Self::Realm(s) |
			Self::Nonce(s) | Self::Software(s) => {
				data.copy_from_slice(s.as_bytes());
			},
			Self::Integrity(v) => data.copy_from_slice(v.as_ref()),
			Self::Error{code, message} => {
				data[0] = 0;
				data[1] = 0;
				data[2] = (code / 100) as u8;
				data[3] = (code % 100) as u8;
				data[4..].copy_from_slice(message.as_bytes());
			},
			Self::UnknownAttributes(ua) => ua.encode(data),
			Self::Fingerprint(v) | Self::Channel(v) | Self::Lifetime(v) |
			Self::ReservationToken(v) | Self::Priority(v) => data.copy_from_slice(&v.to_be_bytes()),
			Self::Data(v) | Self::Other(_, v) => data.copy_from_slice(&v),
			Self::EvenPort(b) => data[0] = match b { true => 0b10000000, false => 0},
			Self::RequestedTransport(protocol) => data[0] = *protocol,
			Self::DontFragment | Self::UseCandidate => {/* Do Nothing */},
			Self::IceControlled(v) | Self::IceControlling(v) => data.copy_from_slice(&v.to_be_bytes()),
		}

		while length % 4 != 0 {
			buff[4 + length as usize] = 0;
			length += 1;
		}
	}
}
