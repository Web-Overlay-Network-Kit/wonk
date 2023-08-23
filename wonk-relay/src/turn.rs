use eyre::eyre;
use std::net::SocketAddr;

use stun_zc::{
	attr::{AttrContext, Data, Error, StunAttr, StunAttrValue},
	attrs::StunAttrs,
	Stun, StunTyp,
};

#[derive(Debug, Clone)]
pub struct TurnUsername {
	full: Box<str>,
	len_1: usize,
	len_2: usize,
	len_3: usize
}
impl TurnUsername {
	pub fn dst(&self) -> &str {
		&self.full[0..self.len_1]
	}
	pub fn src(&self) -> &str {
		&self.full[self.len_1 + 1..][..self.len_2]
	}
	pub fn token(&self) -> &str {
		&self.full[self.len_1 + 1 + self.len_2 + 1..][..self.len_3]
	}
}
impl TryFrom<&str> for TurnUsername {
	type Error = eyre::Report;
	fn try_from(value: &str) -> Result<Self, Self::Error> {
		let mut split = value.split(".");
		let dst = split.next().ok_or(eyre!("too short"))?;
		let src = split.next().ok_or(eyre!("too short"))?;
		let token = split.next().ok_or(eyre!("too short"))?;
		if dst.is_empty() || src.is_empty() || token.is_empty() {
			Err(eyre!("too empty"))
		} else {
			Ok(Self {
				full: value.to_string().into_boxed_str(),
				len_1: dst.len(),
				len_2: src.len(),
				len_3: token.len(),
			})
		}
	}
}
impl AsRef<str> for TurnUsername {
	fn as_ref(&self) -> &str {
		&self.full
	}
}

#[derive(Debug, Clone)]
pub enum TurnReq<'i> {
	Channel {
		channel: u16,
		data: &'i [u8],
	},
	Send {
		txid: &'i [u8; 12],
		xpeer: SocketAddr,
		data: &'i [u8],
	},
	Binding {
		txid: &'i [u8; 12],
	},
	AllocateNoAuth {
		txid: &'i [u8; 12],
	},
	Allocate {
		txid: &'i [u8; 12],
		username: &'i str,
		key_data: [u8; 16],
		requested_transport: u8,
		// dont_fragment, even_port, reservation_token
	},
	Permission {
		txid: &'i [u8; 12],
		username: &'i str,
		key_data: [u8; 16],
		xpeer: SocketAddr,
	},
	Refresh {
		txid: &'i [u8; 12],
		username: &'i str,
		key_data: [u8; 16],
		lifetime: u32,
	},
	BindChannel {
		txid: &'i [u8; 12],
		username: &'i str,
		key_data: [u8; 16],
		channel: u16,
		xpeer: SocketAddr,
	},
}
impl<'i> TurnReq<'i> {
	pub fn decode<F: FnOnce(&str, Option<&str>) -> Option<[u8; 16]>>(
		buff: &'i [u8],
		f: F,
	) -> Option<Self> {
		if buff.len() < 4 {
			return None;
		}
		let typ = u16::from_be_bytes((&buff[0..][..2]).try_into().unwrap());
		let length = u16::from_be_bytes((&buff[2..][..2]).try_into().unwrap());
		match typ {
			// ChannelData:
			0x4000..=0x7fff => {
				if buff.len() < (4 + length as usize) {
					return None;
				}
				Some(Self::Channel {
					channel: typ,
					data: &buff[4..][..length as usize],
				})
			}
			// Stun:
			0..=0x3fff => {
				let msg = Stun::decode(buff).ok()?;
				let txid = msg.txid;
				let flat = msg.flat();
				let auth = flat.check_auth(f);
				Some(match (&msg.typ, auth) {
					(StunTyp::Req(0x001), _) => Self::Binding { txid },
					(StunTyp::Req(0x003), None) => Self::AllocateNoAuth { txid },
					(StunTyp::Req(0x003), Some((username, key_data))) => Self::Allocate {
						txid,
						username,
						key_data,
						requested_transport: flat.requested_transport?,
					},
					(StunTyp::Req(0x008), Some((username, key_data))) => Self::Permission {
						txid,
						username,
						key_data,
						xpeer: flat.xpeer?,
					},
					(StunTyp::Req(0x004), Some((username, key_data))) => Self::Refresh {
						txid,
						username,
						key_data,
						lifetime: flat.lifetime.unwrap_or(3600),
					},
					(StunTyp::Req(0x009), Some((username, key_data))) => Self::BindChannel {
						txid,
						username,
						key_data,
						channel: flat.channel?,
						xpeer: flat.xpeer?,
					},
					(StunTyp::Ind(0x006), None) => Self::Send {
						txid,
						xpeer: flat.xpeer?,
						data: flat.data?,
					},
					_ => {
						return None;
					}
				})
			}
			_ => None,
		}
	}
}

#[derive(Debug, Clone)]
pub enum TurnRes<'i> {
	#[allow(unused)]
	Channel {
		channel: u16,
		data: Data<'i>,
	},
	Data {
		txid: &'i [u8; 12],
		xpeer: SocketAddr,
		data: Data<'i>,
	},
	BindingRes {
		txid: &'i [u8; 12],
		xmapped: SocketAddr,
	},
	AllocateUseAuth {
		txid: &'i [u8; 12],
		realm: &'i str,
		nonce: &'i str,
	},
	AllocateSuc {
		txid: &'i [u8; 12],
		key_data: [u8; 16],
		xmapped: SocketAddr,
		xrelayed: SocketAddr,
		lifetime: u32,
	},
	AllocateMismatch {
		txid: &'i [u8; 12],
		key_data: [u8; 16],
	},
	PermissionSuc {
		txid: &'i [u8; 12],
		key_data: [u8; 16],
	},
	RefreshSuc {
		txid: &'i [u8; 12],
		key_data: [u8; 16],
		lifetime: u32,
	},
	RefreshKick {
		txid: &'i [u8; 12],
		key_data: [u8; 16]
	},
	BindChannelSuc {
		txid: &'i [u8; 12],
		key_data: [u8; 16],
	},
}
impl<'i> TurnRes<'i> {
	pub fn encode(self, buff: &mut [u8]) -> Option<usize> {
		match self {
			Self::Channel { channel, data } => {
				let length = data.length();
				let len = 4 + length as usize;
				if buff.len() < len {
					return None;
				}
				buff[0..][..2].copy_from_slice(&channel.to_be_bytes());
				buff[2..][..2].copy_from_slice(&length.to_be_bytes());
				data.encode(
					&mut buff[4..],
					AttrContext {
						header: &[0u8; 20],
						zero_xor_bytes: false,
						attrs_prefix: &[],
						attr_len: 0,
					},
				);
				return Some(len);
			}
			Self::Data { txid, xpeer, data } => {
				let attrs = [
					StunAttr::XPeer(xpeer),
					StunAttr::Data(data),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Ind(0x007),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::BindingRes { txid, xmapped } => {
				let attrs = [StunAttr::XMapped(xmapped), StunAttr::Fingerprint];
				Stun {
					typ: StunTyp::Res(0x001),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::AllocateUseAuth { txid, realm, nonce } => {
				let attrs = [
					StunAttr::Error(Error {
						code: 401,
						message: "",
					}),
					StunAttr::Realm(realm),
					StunAttr::Nonce(nonce),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Err(0x003),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::AllocateSuc {
				txid,
				key_data,
				xmapped,
				xrelayed,
				lifetime,
			} => {
				let attrs = [
					StunAttr::XMapped(xmapped),
					StunAttr::XRelayed(xrelayed),
					StunAttr::Lifetime(lifetime),
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Res(0x003),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::AllocateMismatch { txid, key_data } => {
				let attrs = [
					StunAttr::Error(Error {
						code: 437,
						message: "",
					}),
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Err(0x003),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::PermissionSuc { txid, key_data } => {
				let attrs = [
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Res(0x008),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::RefreshSuc {
				txid,
				key_data,
				lifetime,
			} => {
				let attrs = [
					StunAttr::Lifetime(lifetime),
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Res(0x004),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::RefreshKick {
				txid,
				key_data
			} => {
				let attrs = [
					StunAttr::Error(Error { code: 500, message: "Get kicked!" }),
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Err(0x004),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
			Self::BindChannelSuc { txid, key_data } => {
				let attrs = [
					StunAttr::Integrity(stun_zc::attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				Stun {
					typ: StunTyp::Res(0x009),
					txid,
					attrs: StunAttrs::List(&attrs),
				}
				.encode(buff)
			}
		}
	}
}
