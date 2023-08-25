use std::net::SocketAddr;

use stun_zc::{
	attr::{Data, Error, Integrity, StunAttr},
	attrs::StunAttrs,
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
	pub fn encode(&self) -> WebRTCEncoded<'i> {
		match self {
			Self::Dtls(b) => WebRTCEncoded::Slice(b),
			Self::Rtp(b) => WebRTCEncoded::Slice(b),
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
				if *use_candidate {
					WebRTCEncoded::Stun6(typ, txid.clone(), [
						StunAttr::Username(username),
						ice_cont,
						StunAttr::UseCandidate,
						StunAttr::Priority(*priority),
						StunAttr::Integrity(integrity.clone()),
						StunAttr::Fingerprint
					])
				} else {
					WebRTCEncoded::Stun5(typ, txid.clone(), [
						StunAttr::Username(username),
						ice_cont,
						StunAttr::Priority(*priority),
						StunAttr::Integrity(integrity.clone()),
						StunAttr::Fingerprint
					])
				}
			}
			Self::IceRes {
				txid,
				xmapped,
				integrity,
			} => {
				WebRTCEncoded::Stun3(StunTyp::Res(0x001), txid.clone(), [
					StunAttr::XMapped(*xmapped),
					StunAttr::Integrity(integrity.clone()),
					StunAttr::Fingerprint
				])
			}
			Self::IceErr {
				txid,
				integrity,
				error,
			} => {
				WebRTCEncoded::Stun3(StunTyp::Err(0x001), txid.clone(), [
					StunAttr::Error(error.clone()),
					StunAttr::Integrity(integrity.clone()),
					StunAttr::Fingerprint
				])
			}
		}
	}
}

pub enum WebRTCEncoded<'i> {
	Slice(&'i [u8]),
	Stun3(StunTyp, [u8; 12], [StunAttr<'i>; 3]),
	Stun5(StunTyp, [u8; 12], [StunAttr<'i>; 5]),
	Stun6(StunTyp, [u8; 12], [StunAttr<'i>; 6]),
}
impl<'i> From<&'i WebRTCEncoded<'i>> for Data<'i> {
	fn from(value: &'i WebRTCEncoded<'i>) -> Self {
		match value {
			WebRTCEncoded::Slice(s) => Self::Slice(s),
			WebRTCEncoded::Stun3(typ, txid, attrs) => Self::Nested(Stun {
				typ: typ.clone(), txid: txid.clone(), attrs: StunAttrs::List(attrs)
			}),
			WebRTCEncoded::Stun5(typ, txid, attrs) => Self::Nested(Stun {
				typ: typ.clone(), txid: txid.clone(), attrs: StunAttrs::List(attrs)
			}),
			WebRTCEncoded::Stun6(typ, txid, attrs) => Self::Nested(Stun {
				typ: typ.clone(), txid: txid.clone(), attrs: StunAttrs::List(attrs)
			}),
		}
	}
}
