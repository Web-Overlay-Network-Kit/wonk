import { pid } from 'wonk-identity';
import { PeerId, b64url } from 'wonk-peerid';

/**
 * === Examples (Aspirational, not working yet) ===
 * relayu:OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio@local.evan-brass.net:4666
 * - Connect via a proxy (turn:local.evan-brass.net:4666?transport=udp)
 * - Connect to peer OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio
 * - Randomly generate a token for the connection (Not answering an existing connection)
 * 
 * relayl:OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio:MJfyvbCdukmQpaow-vAqXg@local.evan-brass.net
 * - Answer a connection from OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio (identified via token MJfyvbCdukmQpaow-vAqXg)
 * - Connect via a proxy (turns:local.evan-brass.net:443)
 * 
 * TODO:
 * udp:OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio:this/is/ice/password@node.evan-brass.net
 * - Server is ICE light (no proxy)
 *   - ICE ufrag: OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio (same as peerid)
 *   - ICE pwd: this/is/ice/password (if not set, then the/ice/password/constant)
 * 
 * web+kad:OW-4EPSfaEAJ8eljpvKOVW_gqJPUwV5-K2G0ulT1Qio/p2p-chat
 * - Connect via auto discovery
 * - Create a datachannel on that connection to the p2p-chat service
 */

export function gen_token(len = 16) {
	const bytes = crypto.getRandomValues(new Uint8Array(len));
	return b64url.btoa_url(b64url.buftobinstr(bytes));
}

const proto_turn = {
	relayt: 'turn',
	relayl: 'turns',
	relayu: 'turn'
};
const proto_search = {
	relayt: '?transport=tcp',
	relayl: '?transport=tcp',
	relayu: '?transport=udp'
};
const proto_ports = {
	relayt: 3478,
	relayl: 5349,
	relayu: 3478
};


export class Address {
	#a;
	#b;
	protocol = 'relayl';
	constructor(s = 'relayl:localhost') {
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
		return new PeerId(this.inner.username);
	}
	set peer_id(peer_id) {
		this.#a.username = String(peer_id);
		this.#b.username = String(peer_id);
	}
	get urls() {
		return [`${proto_turn[this.protocol]}:${this.hostname}:${this.port}${proto_search[this.protocol]}`];
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
