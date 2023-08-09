use stun::{Stun, StunAuth, StunType, attr::StunAttr};
use eyre::Result;
use std::{net::{UdpSocket, SocketAddr}, collections::HashMap};

fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buff = [0u8; 4096];
	let mut out_buff = [0u8; 4096];

	let mut _associations: HashMap<SocketAddr, String> = HashMap::new();

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

		// TURN Allocate
		if let StunType::Req(0x003) = msg.typ {
			let len = if msg.into_iter().all(|a| match a { StunAttr::Integrity(_) => false, _ => true }) {
				let attrs = [
					StunAttr::Error { code: 401, message: "".into() },
					StunAttr::Nonce("nonce".into()),
					StunAttr::Realm("realm".into())
				];
				msg.err(&attrs).encode(&mut out_buff, StunAuth::NoAuth, true)?
			} else {
				let username = msg.into_iter().find_map(|a| match a { StunAttr::Username(s) => Some(s), _ => None })
					.expect("Shouldn't have passed integrity check without a username.");
				
				// TODO: Map the socketaddr to the associated username, and if there's already an association, then return an error

				let auth = StunAuth::Static { username, realm: Some("realm"), password: "the/turn/password/constant" };
				let attrs = [
					StunAttr::XRelayed(addr),
					StunAttr::XMapped(addr),
					StunAttr::Lifetime(3600)
				];
				msg.res(&attrs).encode(&mut out_buff, auth, true)?
			};
			sock.send_to(&out_buff[..len], addr)?;
		}
	}
}
