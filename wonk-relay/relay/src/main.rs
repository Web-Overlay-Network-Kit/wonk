use stun::{Stun, StunAuth, StunType, attr::StunAttr};
use eyre::Result;
use std::{net::{UdpSocket, SocketAddr}, collections::HashSet, time::{Instant, Duration}, borrow::Borrow, hash::Hash, ops::Add};
use std::cell::Cell;

#[allow(unused)]
struct Assoc {
	addr: SocketAddr,
	username: String, // TODO: Replace with (<remote id>, <local id>, <token>)
	ice_username: Cell<Option<String>>,
	expiration: Cell<Instant>,
}
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
impl PartialEq<Assoc> for Assoc {
	fn eq(&self, other: &Assoc) -> bool {
		self.addr == other.addr
	}
}
impl Eq for Assoc {}

const REALM: &str = "realm";
const TURN_PWD: &str = "the/turn/password/constant";

fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buff = [0u8; 4096];
	let mut out_buff = [0u8; 4096];


	let mut assocs: HashSet<Assoc> = HashSet::new();

	loop {
		out_buff.fill(0);
		let Ok((len, addr)) = sock.recv_from(&mut buff) else { continue; };
		let packet = &buff[..len];
		let msg = match Stun::decode(packet, StunAuth::Get(&|_, realm| match realm {
			Some("realm") => Some("the/turn/password/constant"),
			_ => None
		})) {
			Ok(m) => m,
			Err(e) => {
				eprintln!("Error: {e}");
				continue;
			}
		};

		// STUN Binding Requests:
		if let StunType::Req(0x001) = msg.typ {
			let attrs = [
				StunAttr::Mapped(addr),
				StunAttr::XMapped(addr)
			];
			let len = msg.res(&attrs).encode(&mut out_buff, StunAuth::NoAuth, true)?;
			sock.send_to(&out_buff[..len], addr)?;
			continue;
		}

		// Send Indication
		if let StunType::Ind(0x006) = msg.typ {
			// TODO:
			continue;
		}

		// The rest of the operations require authentication:
		let Some((username, realm)) = msg.auth_info() else {
			let attrs = [
				StunAttr::Error { code: 401, message: "" },
				StunAttr::Nonce("nonce"), // TODO: Check the nonce elsewhere?
				StunAttr::Realm(REALM)
			];
			let len = msg.err(&attrs).encode(&mut out_buff, StunAuth::NoAuth, true)?;
			sock.send_to(&out_buff[..len], addr)?;
			continue;
		};
		let auth = StunAuth::Static { username, realm, password: TURN_PWD };

		// TURN Allocate
		if let StunType::Req(0x003) = msg.typ {
			let allow_alloc = assocs.get(&addr).map(|Assoc { username: exp_username, expiration, .. }|
				expiration.get() > Instant::now() || exp_username == username
			).unwrap_or(true);
			let len = if allow_alloc {
				let valid_dur = 3600;

				assocs.insert(Assoc { addr, username: username.to_owned(), expiration: Instant::now().add(Duration::from_secs(valid_dur as u64)).into(), ice_username: None.into() });

				let attrs = [
					StunAttr::XRelayed(addr),
					StunAttr::XMapped(addr),
					StunAttr::Lifetime(valid_dur)
				];
				msg.res(&attrs).encode(&mut out_buff, auth, true)?
			} else {
				let attrs = [
					StunAttr::Error { code: 437, message: "" }
				];
				msg.err(&attrs).encode(&mut out_buff, auth, true)?
			};
			sock.send_to(&out_buff[..len], addr)?;
			continue;
		}

		// All other messages require an existing association:
		let Some(assoc) = assocs.get(&addr) else {
			let attrs = [
				StunAttr::Error { code: 437, message: "" }
			];
			let len = msg.err(&attrs).encode(&mut out_buff, auth, true)?;
			sock.send_to(&out_buff[..len], addr)?;
			continue;
		};

		// TURN Permission:
		let len = if let StunType::Req(0x008) = msg.typ {
			msg.res(&[]).encode(&mut out_buff, auth, true)?
		}
		// TURN Refresh:
		else if let StunType::Req(0x004) = msg.typ {
			let Some(lifetime) = msg.into_iter().find_map(|a| match a { StunAttr::Lifetime(l) => Some(l), _ => None }) else { continue; };
			if lifetime == 0 {
				assocs.remove(&addr);
			} else {
				assoc.expiration.replace(Instant::now().add(Duration::from_secs(lifetime as u64)));
			}
			msg.res(&[]).encode(&mut out_buff, auth, true)?
		}
		else { continue; };
		sock.send_to(&out_buff[..len], addr)?;
	}
}
