use eyre::{Result, eyre};
use std::net::{TcpListener, IpAddr};

enum StunKind {
	Request(u16),
	Indication(u16),
	Error(u16),
	Response(u16)
}
enum StunAttribute {
	MappedAddress(IpAddr), // This is actually an XOR-MAPPED-ADDRESS
	Username(String),
	ErrorCode(u16, String),
	Realm(String),
	Nonce(String),
	ChannelNumber(u16),
	Lifetime(u32),
	PeerAddress(IpAddr),
	Data(Vec<u8>),
	RelayedAddress()
	Other(u16, Vec<u8>)
}
struct Stun {
	kind: StunKind,
	txid: [u8; 12],
	attributes: Vec<StunAttribute>
}

fn main() -> Result<()> {
	let listener = TcpListener::bind("[::]:80")?;

	loop {
		let Ok((stream, _)) = listener.accept() else { continue; };

	}
}
