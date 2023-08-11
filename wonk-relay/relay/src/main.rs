use eyre::Result;
use std::cell::Cell;
use std::{
	borrow::Borrow,
	collections::HashSet,
	hash::Hash,
	net::{SocketAddr, UdpSocket},
	ops::Add,
	time::{Duration, Instant},
};
use stun::{attr::StunAttr, Stun, StunAuth, StunType};

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
const ICE_PWD: &str = "the/ice/password/constant";

fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buff = [0u8; 4096];
	let mut out_buff = [0u8; 4096];

	let mut assocs: HashSet<Assoc> = HashSet::new();

	loop {
		out_buff.fill(0);
		let Ok((len, addr)) = sock.recv_from(&mut buff) else { continue; };
		let packet = &buff[..len];
		let msg = match Stun::decode(
			packet,
			StunAuth::Get(&|_, realm| match realm {
				Some("realm") => Some("the/turn/password/constant"),
				_ => None,
			}),
		) {
			Ok(m) => m,
			Err(e) => {
				eprintln!("Error: {e}");
				continue;
			}
		};

		let auth = match msg.auth_info() {
			Some((username, realm)) => StunAuth::Static {
				username,
				realm,
				password: TURN_PWD,
			},
			None => StunAuth::NoAuth,
		};
		let assoc = assocs.get(&addr);

		let (len, addr) = match (msg.typ, &auth, assoc) {
			// Ignore any indications that lack an association
			(StunType::Ind(_), _, None) => continue,
			// Data Indications
			(StunType::Ind(0x006), _, Some(assoc)) => {
				let Some(data) = msg.into_iter().find_map(|a| match a {
					StunAttr::Data(d) => Some(d), _ => None
				}) else { continue; };
				let Some(first_byte) = data.get(0) else { continue; };
				match first_byte {
					// ICE Binding:
					0..=3 => {
						println!("Help, I'm alive.");
						let res = Stun::decode(data, StunAuth::Get(&|_, _| Some(ICE_PWD)));
						let inner_msg = match res {
							Ok(m) => m,
							Err(e) => {
								eprintln!("{e}");
								continue;
							}
						};
						let Some((username, _)) = inner_msg.auth_info() else { continue };
						println!("{username}");
						match inner_msg.typ {
							StunType::Req(0x001) => {
								todo!();
							},
							StunType::Res(0x001) => {
								continue // TODO: 
							},
							_ => continue
						}
					}
					// DTLS packets:
					20..=63 => {
						continue; // TODO:
					}
					_ => { continue }
				}
			}
			// Binding requests don't require an auth:
			(StunType::Req(0x001), _, _) => {
				let attrs = [StunAttr::Mapped(addr), StunAttr::XMapped(addr)];
				(
					msg.res(&attrs)
						.encode(&mut out_buff, StunAuth::NoAuth, true)?,
					addr,
				)
			}
			// All other requests require a valid auth:
			(StunType::Req(_), StunAuth::NoAuth, _) => {
				let attrs = [
					StunAttr::Error {
						code: 401,
						message: "",
					},
					StunAttr::Nonce("nonce"),
					StunAttr::Realm(REALM),
				];
				(msg.err(&attrs).encode(&mut out_buff, auth, true)?, addr)
			}
			// Allow association if there is no previous association
			(StunType::Req(0x003), StunAuth::Static { username, .. }, None) => {
				let expiration = Instant::now().add(Duration::from_secs(600)).into();
				assocs.insert(Assoc {
					addr,
					username: username.to_string(),
					ice_username: None.into(),
					expiration,
				});
				let attrs = [
					StunAttr::XRelayed(addr),
					StunAttr::XMapped(addr),
					StunAttr::Lifetime(600),
				];
				(msg.res(&attrs).encode(&mut out_buff, auth, true)?, addr)
			}
			// Allow association if the previous association expired, or if the username matches:
			(StunType::Req(0x003), StunAuth::Static { username, .. }, Some(assoc))
				if (assoc.expiration.get() < Instant::now() && *username == assoc.username) =>
			{
				let expiration = Instant::now().add(Duration::from_secs(600)).into();
				assocs.replace(Assoc {
					addr,
					username: username.to_string(),
					ice_username: None.into(),
					expiration,
				});
				let attrs = [
					StunAttr::XRelayed(addr),
					StunAttr::XMapped(addr),
					StunAttr::Lifetime(600),
				];
				(msg.res(&attrs).encode(&mut out_buff, auth, true)?, addr)
			}
			// All other requests require an association
			(StunType::Req(_), _, None) => {
				let attrs = [StunAttr::Error {
					code: 437,
					message: "Association required.",
				}];
				(msg.err(&attrs).encode(&mut out_buff, auth, true)?, addr)
			}
			// TURN Permission
			(StunType::Req(0x008), _, Some(_)) => {
				(msg.res(&[]).encode(&mut out_buff, auth, true)?, addr)
			}
			// TURN Refresh
			(StunType::Req(0x004), _, Some(assoc)) => {
				let lifetime = msg
					.into_iter()
					.find_map(|a| match a {
						StunAttr::Lifetime(l) => Some(l),
						_ => None,
					})
					.unwrap_or(600)
					.min(3600);
				assoc
					.expiration
					.set(Instant::now().add(Duration::from_secs(lifetime as u64)));
				let attrs = [StunAttr::Lifetime(lifetime)];
				(msg.res(&attrs).encode(&mut out_buff, auth, true)?, addr)
			}
			// Ignore everything else:
			_ => continue,
		};
		sock.send_to(&out_buff[..len], addr)?;
	}
}
