import { pid } from 'wonk-identity';
import { PeerId, b64url } from 'wonk-peerid';

export function gen_token(len = 16) {
	const bytes = crypto.getRandomValues(new Uint8Array(len));
	return b64url.btoa_url(b64url.buftobinstr(bytes));
}

const proto_turn = {
	tcp: 'turn',
	tls: 'turns',
	udp: 'turn'
};
const proto_search = {
	tcp: '',
	tls: '',
	udp: '?transport=udp'
};
const proto_ports = {
	tcp: 80,
	tls: 443,
	udp: 3478
};


export class Address {
	#a;
	#b;
	protocol = 'tls';
	constructor(s = 'tls:localhost') {
		this.#a = new URL(s);
		this.#b = new URL(s);

		this.protocol = this.#a.protocol.replaceAll(':', '');

		this.#a.protocol = 'http';
		this.#b.protocol = 'https';
	}

	get inner() {
		return (this.#a.port) ? this.#a : this.#b; // Return whichever inner URL is better
	}

	get token() {
		return this.inner.password;
	}
	set token(token) {
		this.#a.password = token;
		this.#b.password = token;
	}
	get peer_id() {
		return PeerId.from_string(this.inner.username);
	}
	set peer_id(peer_id) {
		this.#a.username = String(peer_id);
		this.#b.username = String(peer_id);
	}
	get urls() {
		return [`${proto_turn[this.protocol]}:${this.host}${proto_search[this.protocol]}`];
	}
	get hostname() {
		return this.inner.hostname;
	}
	set hostname(hostname) {
		this.#a.hostname = hostname;
		this.#b.hostname = hostname;
	}
	get host() {
		return this.inner.host;
	}
	set host(host) {
		this.#a.host = host;
		this.#b.host = host;
	}
	get port() {
		return this.inner.port || proto_ports[this.protocol];
	}
	set port(port) {
		this.#a.port = port;
		this.#b.port = port;
	}

	username(local_id = pid) {
		return `${this.peer_id}.${local_id}.${this.token || gen_token()}`;
	}
	get credential() {
		return 'the/turn/password/constant';
	}
	get ice_pwd() {
		return 'the/ice/password/constant';
	}

	[Symbol.toPrimitive](_hint) {
		return String(this.inner)
			.replace(/https?:\/\//, this.protocol + ':') // Switch to the actual protocol and remove `//` that http has.
			.replace(/\/$/, ''); // Remove trailing slash.
	}
}
