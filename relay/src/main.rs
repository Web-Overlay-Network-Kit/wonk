use std::{
	collections::{HashMap, HashSet},
	net::SocketAddr,
	ops::Add,
	time::{Duration, Instant}
};

use eyre::Result;

mod turn;
use stun::attr::Integrity;
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

#[tokio::main]
async fn main() -> Result<()> {
	let sock = std::net::UdpSocket::bind("[::]:3478")?;
	let mut recv_buff = [0u8; 4096];
	let mut send_buff = [0u8; 4096];

	let mut assocs: HashMap<SocketAddr, Assoc> = HashMap::new();
	let hosted: HashSet<String> = HashSet::new();

	loop {
		let (len, addr) = sock.recv_from(&mut recv_buff)?;
		let Some(msg) = TurnReq::decode(&recv_buff[..len], turn_auth) else { continue; };
		let assoc = assocs.get_mut(&addr);

		let len = match (msg, assoc) {
			(TurnReq::Binding { txid }, _) => TurnRes::BindingRes {
				txid,
				xmapped: addr,
			}
			.encode(&mut send_buff),
			(TurnReq::AllocateNoAuth { txid }, _) => TurnRes::AllocateUseAuth {
				txid,
				realm: "realm",
				nonce: "nonce",
			}
			.encode(&mut send_buff),
			(
				TurnReq::Allocate {
					txid,
					username,
					key_data,
					..
				},
				Some(assoc),
			) if assoc.username.as_ref() != username && assoc.expires < Instant::now() => {
				TurnRes::AllocateMismatch { txid, key_data }.encode(&mut send_buff)
			}
			(
				TurnReq::Allocate {
					txid,
					username,
					key_data,
					..
				},
				_,
			) => {
				let username = username.try_into()?;
				let lifetime = TURN_LIFETIME_SEC;
				let expires = Instant::now()
					.add(Duration::from_secs(lifetime as u64))
					.into();
				println!("{addr} {username:?}");
				assocs.insert(
					addr,
					Assoc {
						username,
						expires,
						ice_username: None
					},
				);
				TurnRes::AllocateSuc {
					txid,
					key_data,
					xmapped: addr,
					xrelayed: addr,
					lifetime,
				}
				.encode(&mut send_buff)
			}
			(
				TurnReq::Refresh {
					username,
					lifetime: 0,
					..
				},
				Some(assoc),
			) if username == assoc.username.as_ref() => {
				assocs.remove(&addr);
				continue;
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
				if hosted.contains(assoc.username.dst()) || hosted.contains(assoc.username.src()) {
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
				}.encode(&mut send_buff)
			}
			(TurnReq::Permission { txid, key_data, .. }, Some(_)) => {
				TurnRes::PermissionSuc { txid, key_data }.encode(&mut send_buff)
			}
			(TurnReq::BindChannel { txid, key_data, .. }, Some(_)) => {
				TurnRes::BindChannelSuc { txid, key_data }.encode(&mut send_buff)
			}
			(TurnReq::Channel { data, .. }, Some(assoc))
			| (TurnReq::Send { data, .. }, Some(assoc)) => {
				let Some(mut webrtc) = WebRTC::decode(data) else { continue; };
				
				if let WebRTC::IceReq { username, .. } = webrtc {
					if let Some((ice_pwd, ice_ufrag)) = username.split_once(":") {
						assoc
						.ice_username
						.get_or_insert_with(|| {
							let ret = format!("{ice_ufrag}:{ice_pwd}");
							ret
						});
					}
				}
				
				// Trade our mutable reference to assoc for an immutable reference to it:
				let assoc = assocs.get(&addr).unwrap();
				
				// TODO: Randomize our traversal of assocs
				for (paddr, peer_assoc) in assocs.iter() {
					if assoc.username.dst() != peer_assoc.username.src() { continue; }
					if assoc.username.src() != peer_assoc.username.dst() { continue; }
					if assoc.username.token() != peer_assoc.username.token() { continue; }
					if peer_assoc.expires < Instant::now() { continue; }
					let Some(ice_username) = peer_assoc.ice_username.as_ref() else { continue; };
					let (_, ice_pwd) = ice_username.split_once(":").unwrap();

					// Fixup the credentials
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
						WebRTC::Rtp(_) => continue, // Don't forward RTP
						_ => {},
					};
					let txid = b"txidtxidtxid"; // TODO: Random?
					if let Some(len) = (TurnRes::Data {
						txid: txid.clone(),
						xpeer: addr,
						data: webrtc.encode()
					}
					.encode(&mut send_buff)) {
						sock.send_to(&send_buff[..len], paddr)?;
					}
				}
				continue;
			}
			_ => continue,
		};
		if let Some(len) = len {
			sock.send_to(&send_buff[..len], addr)?;
		}
	}
}
