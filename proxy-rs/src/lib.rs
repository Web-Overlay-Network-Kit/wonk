use std::{net::IpAddr, str::FromStr};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encode_addr(s: &str, port: u16) -> Option<Vec<u8>> {
	let addr = IpAddr::from_str(s).ok()?;
	let family = match addr {
		IpAddr::V4(_) => 0x01,
		IpAddr::V6(_) => 0x02,
	};
	let mut ret = vec![0, family];
	ret.extend(port.to_be_bytes());
	match addr {
		IpAddr::V4(v4) => ret.extend(v4.octets()),
		IpAddr::V6(v6) => ret.extend(v6.octets()),
	};
	Some(ret)
}
