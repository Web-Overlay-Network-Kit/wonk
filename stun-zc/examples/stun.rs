use std::io::BufRead;

use eyre::Result;
use stun_zc::{attr::StunAttr, Stun, StunTyp, StunDecodeErr};

fn main() -> Result<()> {
	let listener = std::net::TcpListener::bind("[::]:3478")?;

	for stream in listener.incoming().flatten() {
		std::thread::spawn(move || {
			let mut bufread = std::io::BufReader::with_capacity(4096, stream);
			loop {
				let packet = bufread.fill_buf().unwrap();
				let m = match Stun::decode(packet) {
					Err(StunDecodeErr::PacketTooSmall) => continue,
					Err(_) => break,
					Ok(m) => m
				};
				println!("{m:?}");
				let len = m.len();
				bufread.consume(len);
			}
		});
	}

	let sock = std::net::UdpSocket::bind("[::]:3478")?;
	let mut recv_buff = [0u8; 4096];
	let mut send_buff = [0u8; 4096];
	loop {
		let (len, addr) = sock.recv_from(&mut recv_buff)?;
		let res = Stun::decode(&recv_buff[..len]);
		let m = match res {
			Err(e) => {
				eprintln!("{e:?}");
				continue;
			}
			Ok(m) => m,
		};
		println!("{addr} {:?} {:?}", m.typ, m.txid);
		for a in &m {
			println!(" - {a:?}");
		}

		match m.typ {
			StunTyp::Req(0x001) => {
				let attrs = [
					// StunAttr::Mapped(addr.into()),
					StunAttr::XMapped(addr),
					StunAttr::Software("stun-zc: stun.rs"),
					StunAttr::Fingerprint,
				];
				let len = m
					.res(&attrs)
					.encode(&mut send_buff)
					.expect("Couldn't fit a BindingResponse in 4kb?");
				sock.send_to(&send_buff[..len], addr)?;
			}
			_ => continue,
		}
	}
}
