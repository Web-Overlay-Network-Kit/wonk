use std::{
	borrow::Borrow,
	cell::Cell,
	collections::HashSet,
	hash::Hash,
	net::SocketAddr,
	ops::Add,
	time::{Duration, Instant},
};

use eyre::Result;

mod turn;
use turn::{TurnReq, TurnRes};

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
#[allow(unused)]
fn ice_auth(_: &str, realm: Option<&str>) -> Option<&'static [u8]> {
	if let Some(_) = realm {
		return None;
	}

	Some(b"the/ice/password/constant")
}

#[allow(unused)]
pub struct Assoc {
	addr: SocketAddr,
	username: String,
	expires: Cell<Instant>,
	ice_username: Cell<Option<String>>,
}
impl PartialEq for Assoc {
	fn eq(&self, other: &Self) -> bool {
		self.addr == other.addr
	}
}
impl Eq for Assoc {}
impl Borrow<SocketAddr> for Assoc {
	fn borrow(&self) -> &SocketAddr {
		&self.addr
	}
}
impl Hash for Assoc {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.addr.hash(state)
	}
}

fn main() -> Result<()> {
	let sock = std::net::UdpSocket::bind("[::]:3478")?;
	let mut recv_buff = [0u8; 4096];
	let mut send_buff = [0u8; 4096];

	let mut assocs: HashSet<Assoc> = HashSet::new();

	loop {
		let (len, addr) = sock.recv_from(&mut recv_buff)?;
		let Some(msg) = TurnReq::decode(&recv_buff[..len], turn_auth) else { continue; };
		let assoc = assocs.get(&addr);

		let len = match (msg, assoc) {
			(TurnReq::Binding { txid }, _) => {
				TurnRes::BindingRes { txid, xmapped: addr }.encode(&mut send_buff)
			},
			(TurnReq::AllocateNoAuth { txid }, _) => {
				TurnRes::AllocateUseAuth { txid, realm: "realm", nonce: "nonce" }.encode(&mut send_buff)
			},
			(TurnReq::Allocate { txid, username, key_data, .. }, Some(assoc)) if assoc.username != username && assoc.expires.get() < Instant::now() => {
				TurnRes::AllocateMismatch { txid, key_data }.encode(&mut send_buff)
			},
			(TurnReq::Allocate { txid, username, key_data, .. }, _) => {
				let username = username.to_owned();
				let lifetime = 3600;
				let expires = Instant::now().add(Duration::from_secs(lifetime as u64)).into();
				assocs.replace(Assoc {
					addr,
					username,
					expires,
					ice_username: None.into(),
				});
				TurnRes::AllocateSuc { txid, key_data, xmapped: addr, xrelayed: addr, lifetime }.encode(&mut send_buff)
			},
			(TurnReq::Refresh { username, lifetime: 0, .. }, Some(assoc)) if username == assoc.username => {
				assocs.remove(&addr);
				continue;
			},
			(TurnReq::Refresh { txid, username, key_data, lifetime }, Some(assoc)) if username == assoc.username => {
				let lifetime = lifetime.min(3600);
				assoc.expires.set(Instant::now().add(Duration::from_secs(lifetime as u64)));
				TurnRes::RefreshSuc { txid, key_data, lifetime }.encode(&mut send_buff)
			},
			(TurnReq::Permission { txid, key_data, .. }, Some(_)) => {
				TurnRes::PermissionSuc { txid, key_data }.encode(&mut send_buff)
			},
			(TurnReq::BindChannel { txid, key_data, .. }, Some(_)) => {
				TurnRes::BindChannelSuc { txid, key_data }.encode(&mut send_buff)
			},
			(TurnReq::Channel { data, .. }, Some(assoc)) |
			(TurnReq::Send { data, .. }, Some(assoc)) => {
				println!("Data {}: {data:?}", assoc.username);
				continue;
			}
			_ => continue,
		};
		if let Some(len) = len {
			sock.send_to(&send_buff[..len], addr)?;
		}
	}
}
