use stun::{Stun, StunAuth, StunType, attr::StunAttr};
use eyre::Result;
use std::net::UdpSocket;

fn main() -> Result<()> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buff = [0u8; 4096];

	loop {
		let Ok((len, addr)) = sock.recv_from(&mut buff) else { continue; };
		let packet = &buff[..len];
		let msg = match Stun::parse_auth(packet, StunAuth::Get(&|_, _| Some("the/turn/password/constant"))) {
			Ok(m) => m,
			Err(e) => {
				eprintln!("Error: {e}");
				continue;
			}
		};
		println!("{addr} {msg:#?}");

		match msg.typ {
			// STUN Binding Req
			StunType::Req(0x001) => {

			}
			// TURN Allocate Req (NoAuth)
			StunType::Req(0x003) if !msg.attrs.contains()=> {

			}
			// TURN Allocate Req (Auth)
			StunType::Req(0x003) => {
				
			}
			_ => {}
		}
	}
}
