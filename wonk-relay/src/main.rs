use std::{
	borrow::Borrow,
	cell::Cell,
	collections::HashSet,
	hash::Hash,
	net::SocketAddr,
	ops::Add,
	time::{Duration, Instant}, str::FromStr,
};

use eyre::Result;
use stun_zc::{
	attr::{self, StunAttr},
	Stun, StunTyp, attrs::StunAttrs,
};

mod turn;

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
fn ice_auth(_: &str, realm: Option<&str>) -> Option<&'static [u8]> {
	if let Some(_) = realm { return None; }

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
		let res = Stun::decode(&recv_buff[..len]);
		let msg = match res {
			Ok(m) => m,
			Err(e) => {
				eprintln!("{e:?}");
				continue;
			}
		};
		let flat = msg.flat();
		// println!("{addr} {:?}", msg.typ);
		// for a in &msg {
		// 	println!("- {a:?}");
		// }

		let auth = flat.check_auth(turn_auth);
		let assoc = assocs.get(&addr);

		match (&msg.typ, assoc, auth) {
			// STUN Bindings don't require authentication:
			(StunTyp::Req(0x001), _, _) => {
				let attrs = [StunAttr::XMapped(addr), StunAttr::Fingerprint];
				let len = msg.res(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// All other Requests do require authentication:
			(StunTyp::Req(_), _, None) => {
				let attrs = [
					StunAttr::Error(attr::Error {
						code: 401,
						message: "",
					}),
					StunAttr::Realm("realm"),
					StunAttr::Nonce("nonce"),
					StunAttr::Fingerprint,
				];
				let len = msg.err(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// TURN Allocate: Existing allocation with non-matching username -> Error
			(StunTyp::Req(0x003), Some(assoc), Some((username, key_data)))
				if assoc.username != username && assoc.expires.get() < Instant::now() =>
			{
				let attrs = [
					StunAttr::Error(attr::Error {
						code: 437,
						message: "",
					}),
					StunAttr::Integrity(attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				let len = msg.err(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// TURN Allocate: No Existing assoc -> Success
			(StunTyp::Req(0x003), _, Some((username, key_data))) => {
				let username = username.to_owned();
				let expires = Instant::now().add(Duration::from_secs(3600)).into();
				assocs.replace(Assoc {
					addr,
					username,
					expires,
					ice_username: None.into(),
				});
				let attrs = [
					StunAttr::XMapped(addr),
					StunAttr::XRelayed(addr),
					StunAttr::Lifetime(3600),
					StunAttr::Integrity(attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				let len = msg.res(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// Every request except allocate requires a valid association:
			(StunTyp::Req(_), Some(assoc), Some((username, key_data)))
				if assoc.username != username || assoc.expires.get() < Instant::now() =>
			{
				let attrs = [
					StunAttr::Error(attr::Error {
						code: 437,
						message: "",
					}),
					StunAttr::Integrity(attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				let len = msg.err(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// TURN Permission: Always success (We ignore permissions)
			(StunTyp::Req(0x008), _, Some((_, key_data))) => {
				let attrs = [
					StunAttr::Integrity(attr::Integrity::Set {
						key_data: &key_data,
					}),
					StunAttr::Fingerprint,
				];
				let len = msg.res(&attrs).encode(&mut send_buff).unwrap();
				sock.send_to(&send_buff[..len], addr)?;
			}
			// TURN Refresh:
			(StunTyp::Req(0x004), Some(assoc), Some((_, key_data))) => {
				let Some(req_lifetime) = flat.lifetime else { continue; };
				if req_lifetime == 0 {
					assocs.remove(&addr);
				} else {
					let lifetime = req_lifetime.min(3600);
					let expires = Instant::now().add(Duration::from_secs(lifetime as u64));
					assoc.expires.set(expires);

					let attrs = [
						StunAttr::Lifetime(lifetime),
						StunAttr::Integrity(attr::Integrity::Set {
							key_data: &key_data,
						}),
						StunAttr::Fingerprint,
					];
					let len = msg.res(&attrs).encode(&mut send_buff).unwrap();
					sock.send_to(&send_buff[..len], addr)?;
				}
			}
			// TURN Send Indication:
			(StunTyp::Ind(0x006), Some(assoc), _) if Instant::now() < assoc.expires.get() => {
				let Some(data) = flat.data else { continue; };
				let Some(xpeer) = flat.xpeer else { continue; };

				let Some(first_byte) = data.get(0) else { continue; };
				match first_byte {
					// STUN:
					0..=3 => {
						let res = Stun::decode(data);
						let inner = match res {
							Ok(m) => m,
							Err(e) => {
								eprintln!("{e:?}");
								continue;
							}
						};
						let inner_flat = inner.flat();

						let Some((_, key_data)) = inner_flat.check_auth(ice_auth) else { continue; };
						let StunTyp::Req(0x001) = inner.typ else { continue; };

						let attrs = [
							StunAttr::XMapped(addr),
							StunAttr::Integrity(attr::Integrity::Set { key_data }),
							StunAttr::Fingerprint
						];
						let attrs = [
							StunAttr::XPeer(xpeer),
							StunAttr::Data(attr::Data::Nested(inner.res(&attrs)))
						];
						let len = Stun {
							typ: StunTyp::Ind(0x007), // Data Indication
							txid: msg.txid,
							attrs: StunAttrs::List(&attrs)
						}.encode(&mut send_buff).unwrap();
						sock.send_to(&send_buff[..len], addr)?;
					}
					// DTLS
					20..=63 => {
						// Toss the DTLS packets to :4666 so we can inspect them from wireshark
						sock.send_to(data, SocketAddr::from_str("[::1]:4666")?)?;
					}
					_ => {}
				}
			}
			_ => {}
		}
	}
}
