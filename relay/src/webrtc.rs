use std::net::SocketAddr;

use stun::{
	attr::{Data, Error, Integrity, StunAttr},
	Stun, StunTyp,
};

#[derive(Debug, Clone)]
pub enum WebRTC<'i> {
	IceReq {
		txid: [u8; 12],
		integrity: Integrity<'i>,
		username: &'i str,

		priority: u32,
		tie_breaker: u64,
		is_controlling: bool,
		use_candidate: bool,
	},
	IceRes {
		txid: [u8; 12],
		xmapped: SocketAddr,
		integrity: Integrity<'i>,
	},
	IceErr {
		txid: [u8; 12],
		integrity: Integrity<'i>,
		error: Error<'i>,
	},
	Dtls(&'i [u8]),
	Rtp(&'i [u8]),
}
impl<'i> WebRTC<'i> {
	pub fn decode(buff: &'i [u8]) -> Option<Self> {
		let first_byte = buff.get(0)?;
		Some(match first_byte {
			0..=3 => {
				let msg = Stun::decode(buff).ok()?;
				let flat = msg.flat();
				match msg.typ {
					StunTyp::Req(0x001) => Self::IceReq {
						txid: msg.txid,
						integrity: flat.integrity?,
						username: flat.username?,
						priority: flat.priority?,
						tie_breaker: flat.ice_controlling.or(flat.ice_controlled)?,
						is_controlling: flat.ice_controlling.is_some(),
						use_candidate: flat.use_candidate.is_some(),
					},
					StunTyp::Res(0x001) => Self::IceRes {
						txid: msg.txid,
						xmapped: flat.xmapped?,
						integrity: flat.integrity?,
					},
					StunTyp::Err(0x001) => Self::IceErr {
						txid: msg.txid,
						integrity: flat.integrity?,
						error: flat.error?,
					},
					_ => return None,
				}
			}
			20..=63 => Self::Dtls(buff),
			128..=191 => Self::Rtp(buff),
			_ => {
				return None;
			}
		})
	}
	pub fn encode(&self) -> Data<'i> {
		match self {
			Self::Dtls(b) => Data::Slice(b),
			Self::Rtp(b) => Data::Slice(b),
			Self::IceReq {
				txid,
				integrity,
				username,
				priority,
				tie_breaker,
				is_controlling,
				use_candidate,
			} => {
				let ice_cont = if *is_controlling {
					StunAttr::IceControlling(*tie_breaker)
				} else {
					StunAttr::IceControlled(*tie_breaker)
				};
				let typ = StunTyp::Req(0x001);
				let mut attrs = vec![
					StunAttr::Username(username),
					ice_cont,
					StunAttr::Priority(*priority),
					StunAttr::Integrity(integrity.clone()),
					StunAttr::Fingerprint
				];
				if *use_candidate { attrs.insert(2, StunAttr::UseCandidate) }
				Data::Nested(Stun {
					typ,
					txid: txid.clone(),
					attrs
				})
			}
			Self::IceRes {
				txid,
				xmapped,
				integrity,
			} => {
				Data::Nested(Stun {
					typ: StunTyp::Res(0x001), 
					txid: txid.clone(), 
					attrs: vec![
						StunAttr::XMapped(*xmapped),
						StunAttr::Integrity(integrity.clone()),
						StunAttr::Fingerprint
					]
				})
			}
			Self::IceErr {
				txid,
				integrity,
				error,
			} => {
				Data::Nested(Stun {
					typ: StunTyp::Err(0x001),
					txid: txid.clone(),
					attrs: vec![
						StunAttr::Error(error.clone()),
						StunAttr::Integrity(integrity.clone()),
						StunAttr::Fingerprint
					]
				})
			}
		}
	}
}
