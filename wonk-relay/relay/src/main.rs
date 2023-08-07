use stun::{Stun, StunAuth, StunType, attr::StunAttr};
use eyre::Result;
use std::{net::UdpSocket, borrow::Cow};

fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buff = [0u8; 4096];

	loop {
		let Ok((len, addr)) = sock.recv_from(&mut buff) else { continue; };
		let packet = &buff[..len];
		let msg = match Stun::decode(packet, StunAuth::Get(&|_, _| Some("the/turn/password/constant"))) {
			Ok(m) => m,
			Err(e) => {
				eprintln!("Error: {e}");
				continue;
			}
		};
		// println!("{addr} {msg:#?}");

		match msg.typ {
			// STUN Binding Req
			StunType::Req(0x001) => {

			}
			// TURN Allocate Req (Auth)
			StunType::Req(0x003) => {
				let attrs = [
					StunAttr::Error { code: 401, message: "".into() },
					StunAttr::Nonce("nonce".into()),
					StunAttr::Realm("realm".into())
				];
				let response = Stun {
					typ: StunType::Err(0x003),
					txid: msg.txid,
					attrs: Cow::Borrowed(&attrs)
				};
				let mut buff = Vec::new();
				response.encode(&mut buff);
				sock.send_to(&buff, addr)?;
			}
			_ => {}
		}
	}
}
