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
	pub fn encode(&self, buff: &mut Vec<u8>) {
		match self {
			Self::Parse(s) => buff.extend_from_slice(s),
			Self::List(l) => for t in l.as_ref() {
				buff.extend_from_slice(&t.to_be_bytes())
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

fn stun_addr_attr(data: &[u8], xor_bytes: Option<&[u8]>) -> Result<SocketAddr> {
	if data.len() < 4 { return Err(eyre!("STUN Address type attribute is too short ({}).", data.len())); }
	let family = data[1];
	let port_bytes = std::array::from_fn(|i| {
		data[2 + i] ^ xor_bytes.map(|s| s[i]).unwrap_or_default()
	});
	let port = u16::from_be_bytes(port_bytes);
	let ip = match family {
		0x01 => {
			if data.len() != 8 { return Err(eyre!("STUN Address type attribute is wrong size ({}) for family ({family}).", data.len())); }
			let ip_bytes: [u8; 4] = std::array::from_fn(|i| {
				data[4 + i] ^ xor_bytes.map(|s| s[i]).unwrap_or_default()
			});
			IpAddr::from(ip_bytes)
		},
		0x02 => {
			if data.len() != 20 { return Err(eyre!("STUN Address type attribute is wrong size ({}) for family ({family}).", data.len())); }
			let ip_bytes: [u8; 16] = std::array::from_fn(|i| {
				data[4 + i] ^ xor_bytes.map(|s| s[i]).unwrap_or_default()
			});
			IpAddr::from(ip_bytes)
		},
		_ => { return Err(eyre!("STUN Address attribute unknown family ({family}).")); }
	};
	Ok(SocketAddr::new(ip, port))
}

fn encode_addr_attr(addr: &SocketAddr, buff: &mut Vec<u8>, xor_bytes: Option<&[u8]>) {
	buff.push(0);
	let family = if addr.is_ipv4() { 0x01 } else { 0x02 };
	buff.push(family);
	
	let xor_bytes = || xor_bytes.iter().cloned().flatten().cloned().chain(std::iter::repeat(0));

	buff.extend(addr.port().to_be_bytes().into_iter().zip(xor_bytes()).map(|(a, b)| a ^ b));
	match addr.ip() {
		IpAddr::V4(ip) => buff.extend(ip.octets().into_iter().zip(xor_bytes()).map(|(a, b)| a ^ b)),
		IpAddr::V6(ip) => buff.extend(ip.octets().into_iter().zip(xor_bytes()).map(|(a, b)| a ^ b))
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
	pub fn len(&self) -> u16 {
		match self {
			Self::Mapped(s) | Self::XMapped(s) |
			Self::AlternateServer(s) | Self::XPeer(s) |
			Self::XRelayed(s) => match s {
				SocketAddr::V4(_) => 8,
				SocketAddr::V6(_) => 20
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
	pub fn parse(typ: u16, data: &'i[u8], xor_bytes: &'_[u8]) -> Result<Self> {
		Ok(match typ {
			0x0001 => Self::Mapped(stun_addr_attr(data, None)?),
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
			0x0020 => Self::XMapped(stun_addr_attr(data, Some(xor_bytes))?),
			0x8022 => Self::Software(std::str::from_utf8(data)?.into()),
			0x8023 => Self::AlternateServer(stun_addr_attr(data, None)?),
			0x8028 => Self::Fingerprint(u32::from_be_bytes(data.try_into()?)),

			0x000C => Self::Channel(u32::from_be_bytes(data.try_into()?)),
			0x000D => Self::Lifetime(u32::from_be_bytes(data.try_into()?)),
			0x0012 => Self::XPeer(stun_addr_attr(data, Some(xor_bytes))?),
			0x0013 => Self::Data(data.into()),
			0x0016 => Self::XRelayed(stun_addr_attr(data, Some(xor_bytes))?),
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
	pub fn encode(&self, buff: &mut Vec<u8>, xor_bytes: &[u8]) {
		// TODO: I can't use xor_bytes, because it would be an immutable borrow of buff which is also borrowed mutably.
		
		buff.extend_from_slice(&self.typ().to_be_bytes());
		buff.extend_from_slice(&self.len().to_be_bytes());

		match self {
			Self::Mapped(s) | Self::AlternateServer(s) => encode_addr_attr(s, buff, None),
			Self::XMapped(s) | Self::XPeer(s) | Self::XRelayed(s) => encode_addr_attr(s, buff, Some(xor_bytes)),
			Self::Username(s) | Self::Realm(s) |
			Self::Nonce(s) | Self::Software(s) => {
				buff.extend_from_slice(s.as_bytes());
			},
			Self::Integrity(v) => buff.extend_from_slice(v.as_ref()),
			Self::Error{code, message} => {
				buff.push(0);
				buff.push(0);
				buff.push((code / 100) as u8);
				buff.push((code % 100) as u8);
				buff.extend_from_slice(message.as_bytes());
			},
			Self::UnknownAttributes(ua) => ua.encode(buff),
			Self::Fingerprint(v) | Self::Channel(v) | Self::Lifetime(v) |
			Self::ReservationToken(v) | Self::Priority(v) => buff.extend_from_slice(&v.to_be_bytes()),
			Self::Data(v) | Self::Other(_, v) => buff.extend_from_slice(&v),
			Self::EvenPort(b) => buff.push(match b { true => 0b10000000, false => 0}),
			Self::RequestedTransport(protocol) => buff.push(*protocol),
			Self::DontFragment | Self::UseCandidate => {/* Do Nothing */},
			Self::IceControlled(v) | Self::IceControlling(v) => buff.extend_from_slice(&v.to_be_bytes()),
		}

		while buff.len() % 4 != 0 {
			buff.push(0);
		}
	}
}
