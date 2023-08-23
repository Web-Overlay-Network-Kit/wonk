use std::{
	collections::{HashMap, HashSet},
	net::SocketAddr,
	ops::Add,
	time::{Duration, Instant}
};
use tokio::net::UdpSocket;

use eyre::Result;

mod turn;
use stun_zc::attr::Integrity;
use turn::{TurnReq, TurnRes, TurnUsername};

use crate::webrtc::WebRTC;
mod webrtc;

fn turn_auth(username: &str, realm: Option<&str>) -> Option<[u8; 16]> {
	let realm = realm?;
	let mut hasher = md5::Context::new();
	hasher.consume(username);
	hasher.consume(":");
	hasher.consume(realm);
	hasher.consume(":");
	hasher.consume("the/turn/password/constant");

	Some(hasher.compute().into())
}
const ICE_PWD: &[u8] = b"the/ice/password/constant";

#[allow(unused)]
pub struct Assoc {
	username: TurnUsername,
	expires: Instant,
	ice_username: Option<String>
}

const TURN_LIFETIME_SEC: u32 = 60;

enum TurnOp<'i> {
	Respond(TurnRes<'i>),
	Data(&'i [u8]),
	Nothing
}

fn handle_turn<'i>(hosted: &HashSet<String>, addr: SocketAddr, req: TurnReq<'i>, assoc: Option<&mut Assoc>) -> TurnOp<'i> {
	match (req, assoc) {
		(TurnReq::Binding { txid }, _) => TurnOp::Respond(TurnRes::BindingRes {
			txid,
			xmapped: addr,
		}),
		(TurnReq::AllocateNoAuth { txid }, _) => TurnOp::Respond(TurnRes::AllocateUseAuth {
			txid,
			realm: "realm",
			nonce: "nonce",
		}),
		(
			TurnReq::Allocate {
				txid,
				username,
				key_data,
				..
			},
			Some(assoc),
		) if assoc.username.as_ref() != username && assoc.expires < Instant::now() => TurnOp::Respond(TurnRes::AllocateMismatch { txid, key_data }),
		(
			TurnReq::Allocate {
				txid,
				username,
				key_data,
				..
			},
			_,
		) => {
			let Ok(username) = TurnUsername::try_from(username) else { return TurnOp::Nothing };
			let lifetime = TURN_LIFETIME_SEC;
			// let expires = Instant::now()
			// 	.add(Duration::from_secs(lifetime as u64))
			// 	.into();
			println!("{addr} {username:?}");
			// TODO: Enable Assoc modification
			// assocs.insert(
			// 	addr,
			// 	Assoc {
			// 		username,
			// 		expires,
			// 		ice_username: None
			// 	},
			// );
			TurnOp::Respond(TurnRes::AllocateSuc {
				txid,
				key_data,
				xmapped: addr,
				xrelayed: addr,
				lifetime,
			})
		}
		(
			TurnReq::Refresh {
				username,
				lifetime: 0,
				..
			},
			Some(assoc),
		) if username == assoc.username.as_ref() => {
			// TODO: Enable Assoc modification
			// assocs.remove(&addr);
			TurnOp::Nothing
		}
		(
			TurnReq::Refresh {
				txid,
				username,
				key_data,
				lifetime,
			},
			Some(assoc),
		) if username == assoc.username.as_ref() => {
			TurnOp::Respond(if hosted.contains(assoc.username.dst()) || hosted.contains(assoc.username.src()) {
				let lifetime = lifetime.min(TURN_LIFETIME_SEC);
				assoc.expires = Instant::now().add(Duration::from_secs(lifetime as u64));
				TurnRes::RefreshSuc {
					txid,
					key_data,
					lifetime,
				}
			} else {
				// Kick anything that's not in the hosted
				TurnRes::RefreshKick { txid, key_data }
			})
		}
		(TurnReq::Permission { txid, key_data, .. }, Some(_)) => {
			TurnOp::Respond(TurnRes::PermissionSuc { txid, key_data })
		}
		(TurnReq::BindChannel { txid, key_data, .. }, Some(_)) => {
			TurnOp::Respond(TurnRes::BindChannelSuc { txid, key_data })
		}
		(TurnReq::Channel { data, .. }, Some(_))
		| (TurnReq::Send { data, .. }, Some(_)) => {
			TurnOp::Data(data)
			// let Some(mut webrtc) = WebRTC::decode(data) else { return TurnOp::Nothing };
			
			// if let WebRTC::IceReq { username, .. } = webrtc {
			// 	if let Some((ice_pwd, ice_ufrag)) = username.split_once(":") {
			// 		assoc
			// 		.ice_username
			// 		.get_or_insert_with(|| {
			// 			let ret = format!("{ice_ufrag}:{ice_pwd}");
			// 			ret
			// 		});
			// 	}
			// }
			
			// // Trade our mutable reference to assoc for an immutable reference to it:
			// let assoc = assocs.get(&addr).unwrap();
			
			// // TODO: Randomize our traversal of assocs
			// for (paddr, peer_assoc) in assocs.iter() {
			
			// 	
			// 	
			// }
		},
		_ => TurnOp::Nothing
	}
}
fn fixup_webrtc_creds<'i>(mut webrtc: WebRTC<'i>, ice_username: &'i str) -> WebRTC<'i> {
	let (_, ice_pwd) = ice_username.split_once(":").unwrap();

	match webrtc {
		WebRTC::IceReq {
			ref mut integrity,
			ref mut username,
			ref mut priority,
			..
		} if integrity.verify(ICE_PWD) => {
			*priority = 1;
			*integrity = Integrity::Set {
				key_data: ice_pwd.as_bytes(),
			};
			*username = ice_username;
		}
		WebRTC::IceRes {
			ref mut integrity, ..
		}
		| WebRTC::IceErr {
			ref mut integrity, ..
		} => {
			*integrity = Integrity::Set { key_data: ICE_PWD };
		}
		_ => {},
	}
	webrtc
}

#[tokio::main]
async fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478").await?;
	let mut recv_buff = [0u8; 4096];
	let mut send_buff = [0u8; 4096];

	let mut assocs: HashMap<SocketAddr, Assoc> = HashMap::new();
	let hosted: HashSet<String> = HashSet::new();

	loop {
		let (len, addr) = sock.recv_from(&mut recv_buff).await?;
		let Some(req) = TurnReq::decode(&recv_buff[..len], turn_auth) else { continue; };
		let assoc = assocs.get_mut(&addr);

		match handle_turn(&hosted, addr, req, assoc) {
			TurnOp::Respond(res) => {
				let len = res.encode(&mut send_buff);
				if let Some(len) = len {
					sock.send_to(&send_buff[..len], addr).await?;
				}
			},
			TurnOp::Data(data) => {
				let assoc = assocs.get(&addr).unwrap();
				if let Some(webrtc) = WebRTC::decode(data) {
					for (paddr, passoc) in &assocs {
						if assoc.username.dst() != passoc.username.src() { continue; }
						if assoc.username.src() != passoc.username.dst() { continue; }
						if assoc.username.token() != passoc.username.token() { continue; }
						if passoc.expires < Instant::now() { continue; }
						let Some(ice_username) = passoc.ice_username.as_ref() else { continue; };

						let t = fixup_webrtc_creds(webrtc.clone(), ice_username);
						let txid = b"txidtxidtxid"; // TODO: Random?
						let encoded = t.encode();
						if let Some(len) = (TurnRes::Data {
							txid,
							xpeer: addr,
							data: (&encoded).into()
						}
						.encode(&mut send_buff)) {
							sock.send_to(&send_buff[..len], paddr).await?;
						}
					}
				}
			},
			_ => {}
		}
	}
}
