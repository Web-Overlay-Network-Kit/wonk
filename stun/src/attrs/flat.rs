use std::net::SocketAddr;

use crate::attr::{Integrity, Error, UnknownAttributes, StunAttr, Data};


#[derive(Debug, Clone)]
pub struct Flat<'i> {
	pub mapped: Option<SocketAddr>,
	pub username: Option<&'i str>,
	pub integrity: Option<Integrity<'i>>,
	pub error: Option<Error<'i>>,
	pub unknown_attributes: Option<UnknownAttributes<'i>>,
	pub realm: Option<&'i str>,
	pub nonce: Option<&'i str>,
	pub xmapped: Option<SocketAddr>,
	pub software: Option<&'i str>,
	pub alternate_server: Option<SocketAddr>,
	pub fingerprint: Option<()>,
	pub channel: Option<u16>,
	pub lifetime: Option<u32>,
	pub xpeer: Option<SocketAddr>,
	pub data: Option<&'i [u8]>,
	pub xrelayed: Option<SocketAddr>,
	pub even_port: Option<bool>,
	pub requested_transport: Option<u8>,
	pub dont_fragment: Option<()>,
	pub reservation_token: Option<u32>,
	pub priority: Option<u32>,
	pub use_candidate: Option<()>,
	pub ice_controlled: Option<u64>,
	pub ice_controlling: Option<u64>
}
impl<'i> Flat<'i> {
	// check_auth only works if the packet contains a username.
	pub fn check_auth<T: AsRef<[u8]>, F: FnOnce(&str, Option<&str>) -> Option<T>>(
		&self,
		f: F,
	) -> Option<(&'i str, T)> {
		let username = self.username?;
		let realm = self.realm;
		let integrity = self.integrity.clone()?;
		let password = f(username, realm)?;

		integrity
			.verify(password.as_ref())
			.then_some((username, password))
	}
}
impl<'i> FromIterator<StunAttr<'i>> for Flat<'i> {
	fn from_iter<T: IntoIterator<Item = StunAttr<'i>>>(iter: T) -> Self {
		let mut mapped = None;
		let mut username = None;
		let mut integrity = None;
		let mut error = None;
		let mut unknown_attributes = None;
		let mut realm = None;
		let mut nonce = None;
		let mut xmapped = None;
		let mut software = None;
		let mut alternate_server = None;
		let mut fingerprint = None;
		let mut channel = None;
		let mut lifetime = None;
		let mut xpeer = None;
		let mut data = None;
		let mut xrelayed = None;
		let mut even_port = None;
		let mut requested_transport = None;
		let mut dont_fragment = None;
		let mut reservation_token = None;
		let mut priority = None;
		let mut use_candidate = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;

		for a in iter {
			match a {
				// The .is_none is important because in STUN if attributes are duplicate, only the first attribute is returned
				StunAttr::Mapped(v) if mapped.is_none() => { mapped = Some(v.into())}
				StunAttr::Username(v) if username.is_none() => { username = Some(v) }
				StunAttr::Integrity(v) if integrity.is_none() => {integrity = Some(v) }
				StunAttr::Error(v) if error.is_none() => { error = Some(v) }
				StunAttr::UnknownAttributes(v) if unknown_attributes.is_none() => { unknown_attributes = Some(v) }
				StunAttr::Realm(v) if realm.is_none() => {realm = Some(v)}
				StunAttr::Nonce(v) if nonce.is_none() => {nonce = Some(v)}
				StunAttr::XMapped(v) if xmapped.is_none() => {xmapped = Some(v)}
				StunAttr::Software(v) if software.is_none() => {software = Some(v)}
				StunAttr::AlternateServer(v) if alternate_server.is_none() => {alternate_server = Some(v.into())}
				StunAttr::Fingerprint if fingerprint.is_none() => {fingerprint = Some(())}
				StunAttr::Channel(v) if channel.is_none() => {channel = Some(v.into())}
				StunAttr::Lifetime(v) if lifetime.is_none() => {lifetime = Some(v)}
				StunAttr::XPeer(v) if xpeer.is_none() => {xpeer = Some(v)}
				StunAttr::Data(Data::Slice(v)) if data.is_none() => {data = Some(v)}
				StunAttr::XRelayed(v) if xrelayed.is_none() => {xrelayed = Some(v)}
				StunAttr::EvenPort(v) if even_port.is_none() => {even_port = Some(v.0)}
				StunAttr::RequestedTransport(v) if requested_transport.is_none() => {requested_transport = Some(v.0)}
				StunAttr::DontFragment if dont_fragment.is_none() => {dont_fragment = Some(())}
				StunAttr::ReservationToken(v) if reservation_token.is_none() => {reservation_token = Some(v)}
				StunAttr::Priority(v) if priority.is_none() => {priority = Some(v)}
				StunAttr::UseCandidate if use_candidate.is_none() => {use_candidate = Some(())}
				StunAttr::IceControlled(v) if ice_controlled.is_none() => {ice_controlled = Some(v)}
				StunAttr::IceControlling(v) if ice_controlling.is_none() => {ice_controlling = Some(v)},
				_ => {}
			}
		}

		Self {
			mapped,
			username,
			integrity,
			error,
			unknown_attributes,
			realm,
			nonce,
			xmapped,
			software,
			alternate_server,
			fingerprint,
			channel,
			lifetime,
			xpeer,
			data,
			xrelayed,
			even_port,
			requested_transport,
			dont_fragment,
			reservation_token,
			priority,
			use_candidate,
			ice_controlled,
			ice_controlling,
		}
	}
}
