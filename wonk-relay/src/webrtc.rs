use std::net::SocketAddr;

use stun_zc::{
	attr::{Data, Error, Integrity, StunAttr},
	attrs::StunAttrs,
	Stun, StunTyp,
};

#[derive(Debug, Clone)]
pub enum WebRTC<'i> {
	IceReq {
		txid: &'i [u8; 12],
		integrity: Integrity<'i>,
		username: &'i str,

		priority: u32,
		ice_controlled: Option<u64>,
		ice_controlling: Option<u64>,
		use_candidate: bool,
	},
	IceRes {
		txid: &'i [u8; 12],
		xmapped: SocketAddr,
		integrity: Integrity<'i>,
	},
	IceErr {
		txid: &'i [u8; 12],
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
						ice_controlled: flat.ice_controlled,
						ice_controlling: flat.ice_controlling,
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
	pub fn encode(&self, scratch: &'i mut [StunAttr<'i>; 6]) -> Data<'i> {
		match self {
			Self::Dtls(b) => Data::Slice(b),
			Self::Rtp(b) => Data::Slice(b),
			Self::IceReq {
				txid,
				integrity,
				username,
				priority,
				ice_controlled,
				ice_controlling,
				use_candidate,
			} => {
				let mut i = 0;
				scratch[i] = StunAttr::Username(username);
				i += 1;
				scratch[i] = ice_controlling
					.map(|tb| StunAttr::IceControlling(tb))
					.or(ice_controlled.map(|tb| StunAttr::IceControlled(tb)))
					.unwrap();
				if *use_candidate {
					scratch[i] = StunAttr::UseCandidate;
					i += 1;
				}
				scratch[i] = StunAttr::Priority(*priority);
				i += 1;
				scratch[i] = StunAttr::Integrity(integrity.clone());
				i += 1;
				scratch[i] = StunAttr::Fingerprint;
				i += 1;

				Data::Nested(Stun {
					typ: StunTyp::Req(0x001),
					txid,
					attrs: StunAttrs::List(&scratch[..i]),
				})
			}
			Self::IceRes {
				txid,
				xmapped,
				integrity,
			} => {
				scratch[0] = StunAttr::XMapped(*xmapped);
				scratch[1] = StunAttr::Integrity(integrity.clone());
				scratch[2] = StunAttr::Fingerprint;

				Data::Nested(Stun {
					typ: StunTyp::Res(0x001),
					txid,
					attrs: StunAttrs::List(&scratch[..3]),
				})
			}
			Self::IceErr {
				txid,
				integrity,
				error,
			} => {
				scratch[0] = StunAttr::Error(error.clone());
				scratch[1] = StunAttr::Integrity(integrity.clone());
				scratch[2] = StunAttr::Fingerprint;

				Data::Nested(Stun {
					typ: StunTyp::Err(0x001),
					txid,
					attrs: StunAttrs::List(&scratch[..3]),
				})
			}
		}
	}
}
