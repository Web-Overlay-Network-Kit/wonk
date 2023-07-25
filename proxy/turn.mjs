import { md5 } from './md5.mjs';
import { crc32 } from './crc32.mjs';
import { encode_addr } from 'proxy-rs';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class ParseError extends Error {
	constructor(reason) {
		super(`Parse Error: ${reason}`);
	}
}

export class CredentialManager {
	async short_term(_username, password = 'the/ice/password/constant') {
		const key_data = encoder.encode(password);
		return await crypto.subtle.importKey('raw', key_data, {
			name: 'HMAC',
			hash: 'SHA-1'
		}, false, ['sign', 'verify']);
	}
	async long_term(username, realm, password = 'the/turn/password/constant') {
		const key_data = md5(encoder.encode(`${username}:${realm}:${password}`));
		return await crypto.subtle.importKey('raw', key_data, {
			name: 'HMAC',
			hash: 'SHA-1'
		}, false, ['sign', 'verify']);
	}
}
export class ConnTestCM extends CredentialManager {
	async short_term(username) {
		const [r_ufrag, l_ufrag] = username.split(':');
		if (!r_ufrag || !l_ufrag) return false;

		return await super.short_term(username, l_ufrag); // It's either l_ufrag or r_ufrag... my brain can't figure it our right now so we'll just trial and error it...
	}
}

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
			neww.fill(0, old.byteLength);
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
	#attributes = false;
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
		this.#attributes = false;
		// Pad to 4 bytes:
		while (new_val % 4 != 0) new_val += 1;
		super.length = new_val;
	}
	
	get magic() {
		return this.view.getUint32(4);
	}

	get txid_buf() {
		return new Uint8Array(this.view.buffer, 8, 12);
	}
	get txid() {
		return this.txid_buf.reduce((a, v) => a + String.fromCharCode(v), '');
	}
	set txid(txid) {
		new Uint8Array(this.view.buffer, 8, 12).set(
			txid.split('').map(s => s.charCodeAt(0))
		);
	}

	constructor() {
		super(...arguments);

		if (arguments.length == 0) {
			this.view.setUint32(4, 0x2112A442);
			// Write a random txid as well:
			crypto.getRandomValues(this.txid_buf);
		}
		else if (this.magic != 0x2112A442) throw new Error("Invalid magic value.");

		if (this.length % 4 != 0) throw new Error("STUN not padded.");

		// Check the attributes
		for (const _ of this.attrs()) {}
	}

	async check_auth(credential_manager) {
		
	}
	clear_auth() {
		// Remove any existing fingerprint or message integrity:
		this.remove_attribute(0x8028);
		this.remove_attribute(0x0008);
	}
	async auth(credential_manager) {
		this.clear_auth();
		// TODO:
	}
	fingerprint() {
		this.remove_attribute(0x8028);
	}

	// Attribute helpers
	*attrs() {
		let i = this.constructor.header_size;
		let seen_message_integrity = false;
		while ((i + 4) < (this.constructor.header_size + this.length)) {
			const type = this.view.getUint16(i);
			i += 2;
			const length = this.view.getUint16(i);
			i += 2;
			if (i + length > (this.constructor.header_size + this.length)) throw new ParseError("STUN Attribute has a length that exceed's the packet's length.");
			const value = new DataView(this.view.buffer, this.view.byteOffset + i, length);

			if (type == 0x0008) {
				// We don't check the message integrity because that would be async and requires a credential manager.
				seen_message_integrity = true;
			}

			if (type == 0x8028) {
				// TODO: check the fingerprint
				break;
			}

			// Re-align
			i += length;
			while (i % 4 != 0) i += 1;

			// Don't yield any attributes after the message integrity
			if (seen_message_integrity) continue;

			yield { type, length, value };
		}
	}
	get attr() {
		if (!this.#attributes) {
			const ret = new Map();
			for (const {type, value} of this.attrs()) {
				if (ret.has(type)) continue;
				ret.set(type, value);
			}
			this.#attributes = ret;
		}
		return this.#attributes;
	}
	set_attribute(type, length) {
		const existing = this.attr.get(type);
		let view;
		if (existing) {
			let padded_len = length;
			while (padded_len % 4 != 0) padded_len += 1;
			let existing_padded_len = existing.byteLength;
			while (existing_padded_len % 4 != 0) existing_padded_len += 1;

			if (padded_len != existing_padded_len) {
				this.remove_attribute(type);
			}
			else {
				// Update the length field:
				new DataView(existing.buffer, view.byteOffset - 2, 2).setUint16(length);
				view = existing;
			}
		}
		if (!view) view = this.add_attribute(type, length);

		return view;
	}
	remove_attribute(type) {
		const existing = this.attr.get(type);
		if (!existing) return;

		let remove_len = existing.byteLength + 4;
		while (remove_len % 4 != 0) remove_len += 1;

		const remove_start = existing.byteOffset - 4;
		const before_len = (remove_start - this.view.byteOffset - this.constructor.header_size);
		const shift_len = this.length - before_len - remove_len;

		// Shift the rest of the attributes to overwrite the existing attribute:
		new Uint8Array(existing.buffer, remove_start)
			.set(new Uint8Array(existing.buffer, remove_start + remove_len, shift_len));

		// Adjust the length:
		this.length -= remove_len;

		// Reset the attributes map:
		this.#attributes = false;
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
	get_text_attr(type) {
		const view = this.attr.get(type);
		if (!view) return;
		return decoder.decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
	}
	set_text_attr(type, value) {
		if (typeof value != 'string') {
			this.remove_attribute(type);
		} else {
			const encoded = encoder.encode(value);
			const view = this.set_attribute(type, encoded.byteLength);
			new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
				.set(encoded);
		}
		return true;
	}
	get_buffer_attr(type) {
		const view = this.attr.get(type);
		if (!view) return;
		return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
	}
	set_buffer_attr(type, value) {
		if (value instanceof ArrayBuffer) {
			value = new Uint8Array(value);
		}
		if (!ArrayBuffer.isView(value)) {
			this.remove_attribute(type);
		} else {
			if (!(value instanceof Uint8Array)) {
				value = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
			}
			const view = this.set_attribute(type, value.byteLength);
			new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
				.set(value);
		}
		return true;
	}
	get_addr_attr(type, { transport = 'udp', xor = true } = {}) {
		const view = this.attr.get(type);
		if (!view) return;
		const family = view.getUint8(1);
		const port = view.getUint16(2);
		let addr_bytes = new Uint8Array(view.buffer, view.byteOffset + 4, view.byteLength - 4);
		if (xor) {
			port = port ^ 0x2112;
			addr_bytes = addr_bytes.map((v, i) => v ^ this.view.getUint8(4 + i));
		}
		let hostname = '';
		if (family == 0x01) {
			if (addr_bytes.byteLength != 4) return;
			hostname = addr_bytes.join('.');
		} else if (family == 0x02) {
			if (addr_bytes.byteLength != 16) return;
			const view = new DataView(addr_bytes.buffer, addr_bytes.byteOffset, addr_bytes.byteLength);
			for (let i = 4; i < 20; i += 2) {
				if (!hostname) hostname += ':';
				hostname += view.getUint16(i).toString(16);
			}
		} else {
			return;
		}
		return { hostname, port, transport };
	}
	set_addr_attr(type, value, { xor = true } = {}) {
		if (!value) {
			this.remove_attribute(type);
		} else {
			const { hostname, port = 80 } = value;
			const bytes = encode_addr(hostname, port);
			if (!bytes) throw new Error("Hostname wasn't a valid ip address.");
			const view = this.set_attribute(type, bytes.byteLength);
			if (xor) {
				for (let i = 4; i < bytes.byteLength; i += 1) {
					bytes[i] = bytes[i] ^ this.view.getUint8(4 + i);
				}
			}
			new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
				.set(bytes);
		}
		return true;
	}

	// Attributes: (TODO: DRY)
	get username() {
		return this.get_text_attr(0x0006);
	}
	set username(value) {
		return this.set_text_attr(0x0006, value);
	}
	get realm() {
		return this.get_text_attr(0x0014);
	}
	set realm(value) {
		return this.set_text_attr(0x0014, value);
	}
	get nonce() {
		return this.get_text_attr(0x0015);
	}
	set nonce(value) {
		return this.set_text_attr(0x0015, value);
	}
	get error() {
		const view = this.attr.get(0x0009);
		if (!view) return;
		const code = view.getUint8(2) * 100 + view.getUint8(3);
		const reason = decoder.decode(new Uint8Array(view.buffer, view.byteOffset + 4, view.byteLength - 4));
		return { code, reason };
	}
	set error(error) {
		if (!error) {
			this.remove_attribute(0x0009);
		} else {
			let { code = 404, reason = '' } = error;
			reason = encoder.encode(reason);
			const view = this.add_attribute(0x0009, 4 + reason.byteLength);
			view.setUint16(0, 0);
			view.setUint8(2, Math.trunc(code / 100));
			view.setUint8(3, code % 100);
			new Uint8Array(view.buffer, view.byteOffset + 4, reason.byteLength).set(reason);
		}
		return this;
	}
	get data() {
		return this.get_buffer_attr(0x0013);
	}
	set data(value) {
		return this.set_buffer_attr(0x0013, value);
	}
	get mapped() {
		return this.get_addr_attr(0x0001, {xor: false});
	}
	set mapped(value) {
		return this.set_addr_attr(0x0001, value, {xor: false});
	}
	get xmapped() {
		return this.get_addr_attr(0x0020);
	}
	set xmapped(value) {
		return this.set_addr_attr(0x0020, value);
	}
	get xpeer() {
		return this.get_addr_attr(0x0012);
	}
	set xpeer(value) {
		return this.set_addr_attr(0x0012, value);
	}
	get xrelay() {
		return this.get_addr_attr(0x0016);
	}
	set xrelay(value) {
		return this.set_addr_attr(0x0016, value);
	}

}

export class ChannelData extends Turn {

}
