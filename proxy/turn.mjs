
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class ParseError extends Error {
	constructor(reason) {
		super(`Parse Error: ${reason}`);
	}
}


const named = new Map();
named.set(0x0006, function username(view) { return decoder.decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength)); });
named.set(0x0009, function error() {

});
named.set(0x0014, function realm(view) { return decoder.decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength)); });
named.set(0x0015, function nonce(view) { return decoder.decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength)); });
named.set(0x0020, function addr() {});
named.set(0x000C, function channel() {});
named.set(0x0012, function peer_addr() {});
named.set(0x0013, function data(view) { return new Uint8Array(view.buffer, view.byteOffset, view.byteLength); });

export class Turn {
	view;
	static header_size = 4;
	constructor(view = new DataView(new ArrayBuffer(4096))) {
		this.view = view;
		if (view.byteLength < this.constructor.header_size) throw new ParseError('The view is smaller than the header size for this kind of packet.');
	}
	get packet() {
		return new Uint8Array(this.view.buffer, this.view.byteOffset, this.constructor.header_size + this.length);
	}
	get length() {
		return this.view.getUint16(2);
	}
	set length(new_len) {
		const packet_length = new_len + this.constructor.header_size;
		if (packet_length > this.view.byteLength) {
			// Reallocate the buffer:
			const old = new Uint8Array(this.view.buffer, this.view.byteOffset, this.view.byteLength);
			const neww = new Uint8Array(Math.max(2 * this.view.byteLength, packet_length));
			neww.set(old);
			this.view = new DataView(neww.buffer);
		}
		this.view.setUint16(2, new_len);
	}
	get kind() {
		const a = this.view.getUint16();
		if (a < 0x4000) return 'stun';
		if (a < 0x7fff) return 'data';
		return 'invalid';
	}
	static identify_class(view) {
		const sub_classes = [
			{ prefix: 0x4000, constr: Stun },
			{ prefis: 0x7fff, constr: ChannelData }
		];

		if (view.byteLength < 2) throw new Error("We need at least 2 bytes to identify the class of TURN packet.");
		const a = view.getUint16(0);

		for (const {prefix, constr} of sub_classes) {
			if (a < prefix) return constr;
		}

		throw new ParseError("The packet's prefix doesn't match any class of TURN packet.");
	}
	static packet_len(view) {
		if (view.byteLength < 4) throw new Error("We need at least 4 bytes to calculate the packet's length.");
		const constr = this.identify_class(view);
		const length = view.getUint16(2);
		return constr.header_size + length;
	}
	static parse_packet(view) {
		const constr = this.identify_class(view);
		return new constr(view);
	}
	static async *parse_readable(readable, buff_len = 4096) {
		const reader = readable.getReader({mode: 'byob'});
		let buffer = new ArrayBuffer(buff_len);
		let available = 0;
		let closed = false;
		reader.closed.then(() => closed = true);
		async function need(len) {
			if (len > buffer.byteLength) throw new Error('too big');
			while (available < len) {
				const { done, value: chunk } = await reader.read(new Uint8Array(buffer, available));
				if (!chunk) throw null;

				available += chunk.byteLength;
				buffer = chunk.buffer;

				if (done) throw null;
			}
		}
		try {
			while (1) {
				await need(4);
				let packet_len = this.packet_len(new DataView(buffer, 0, available));
				await need(packet_len);
				const view = new DataView(buffer, 0, packet_len);

				yield this.parse_packet(view);

				// Pad to a 4 byte boundary:
				while (packet_len % 4) packet_len += 1;
				await need(packet_len);

				// shift any remainder
				const remainder = available - packet_len;
				if (remainder > 0) {
					new Uint8Array(buffer, 0, remainder).set(new Uint8Array(buffer, packet_len, remainder));
				}
				available = remainder;
			}
		} catch (e) {
			await reader.cancel(String(e));
			if (e != null) throw e; // Rethrow anything that isn't an end of stream.
		} finally {
			if (!closed) reader.releaseLock();
		}
	}
}

export class Stun extends Turn {
	static header_size = 20;
	get class() {
		const type = this.view.getUint16(0);
		return ((type & 0b00_00000_1_000_0_0000) >> 7) |
		       ((type & 0b00_00000_0_000_1_0000) >> 4);
	}
	set class(new_class) {
		if (new_class > 3) throw new Error('Invalid STUN class');
		this.set_stun_type(new_class, this.method);
	}
	get method() {
		const type = this.view.getUint16(0);
		return ((type & 0b00_11111_0_000_0_0000) >> 2) |
		       ((type & 0b00_00000_0_111_0_0000) >> 1) |
		       ((type & 0b00_00000_0_000_0_1111) >> 0);
	}
	set method(new_method) {
		if (new_method >= 2 ** 12) throw new Error('Invalid STUN method');
		this.set_stun_type(this.class, new_method);
	}
	set_stun_type(clas, method) {
		const type =
			((method << 0) & 0b00_00000_0_000_0_1111) |
			((clas   << 4) & 0b00_00000_0_000_1_0000) |
			((method << 1) & 0b00_00000_0_111_0_0000) |
			((clas   << 7) & 0b00_00000_1_000_0_0000) |
			((method << 2) & 0b00_11111_0_000_0_0000);
		this.view.setUint16(0, type);
	}

	get length() { return super.length; }
	set length(new_val) {
		// Pad to 4 bytes:
		while (new_val % 4 != 0) new_val += 1;
		super.length = new_val;
	}
	
	get magic() {
		return this.view.getUint32(4);
	}

	get txid() {
		return new Uint8Array(this.view.buffer, 8, 12).reduce((a, v) => a + String.fromCharCode(v), '');
	}
	set txid(txid) {
		new Uint8Array(this.view.buffer, 8, 12).set(
			txid.split('').map(s => s.charCodeAt(0))
		);
	}

	constructor() {
		super(...arguments);

		if (arguments.length == 0) this.view.setUint32(4, 0x2112A442);
		else if (this.magic != 0x2112A442) throw new Error("Invalid magic value.");

		if (this.length % 4 != 0) throw new Error("STUN not padded.");

		// Check the attributes
		for (const _ of this.attrs()) {}
	}

	async check_auth() {
		
	}
	async auth() {

	}

	*attrs() {
		let i = this.constructor.header_size;
		while ((i + 4) < (this.constructor.header_size + this.length)) {
			const type = this.view.getUint16(i);
			i += 2;
			const length = this.view.getUint16(i);
			i += 2;
			if (i + length > (this.constructor.header_size + this.length)) throw new ParseError("STUN Attribute has a length that exceed's the packet's length.");
			const value = new DataView(this.view.buffer, this.view.byteOffset + i, length);

			// Re-align
			i += length;
			while (i % 4 != 0) i += 1;

			yield { type, length, value };
		}
	}
	get attributes() {
		const ret = new Map();
		for (const {type, value} of this.attrs()) {
			if (ret.has(type)) continue;
			ret.set(type, value);
			const parse_func = named.get(type);
			if (parse_func) ret.set(parse_func.name, parse_func(value));
		}
		return ret;
	}
	add_attribute(type, length) {
		let i = this.constructor.header_size + this.length;
		this.length += 4 + length;
		this.view.setUint16(i, type);
		this.view.setUint16(i + 2, length);
		const ret = new DataView(this.view.buffer, this.view.byteOffset + i + 4, length);
		new Uint8Array(ret.buffer, ret.byteOffset, ret.byteLength).fill(0);
		return ret;
	}

	set_error(code, reason) {
		reason = encoder.encode(reason);
		const view = this.add_attribute(0x0009, 4 + reason.byteLength);
		view.setUint8(2, Math.trunc(code / 100));
		view.setUint8(3, code % 100);
		new Uint8Array(view.buffer, view.byteOffset + 4, reason.byteLength).set(reason);
		return this;
	}
	set_text(type, text) {
		const encoded = encoder.encode(text);
		const view = this.add_attribute(type, encoded.byteLength);
		new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(encoded);
		return this;
	}
	set_realm(realm) {
		this.set_text(0x0014, realm);
		return this;
	}
	set_nonce(nonce) {
		this.set_text(0x0015, nonce);
		return this;
	}
}

export class ChannelData extends Turn {

}
