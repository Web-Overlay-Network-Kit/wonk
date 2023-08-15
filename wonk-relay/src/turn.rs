

pub enum TurnReq<'i> {
	Channel {
		channel: u16,
		data: &'i [u8]
	},
	Binding {
		txid: &'i [u8; 12],
	},
	AllocateNoAuth {
		txid: &'i [u8; 12],
	},
	Allocate {
		txid: &'i [u8; 12],
		username: &'i str,
		key_data: [u8; 16],
		requested_transport: u8
	}
}
