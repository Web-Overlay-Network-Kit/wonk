import { pid } from 'wonk-identity';
import { PeerId, b64url } from 'wonk-peerid';

function gen_token(len = 16) {
	const bytes = crypto.getRandomValues(new Uint8Array(len));
	return b64url.btoa_url(b64url.buftobinstr(bytes));
}

const proto = {
	t: 'turn', u: 'turn',
	l: 'turns', d: 'turns'
};
const transport = {
	t: '', l: '',
	u: '?transport=udp', d: '?transport=udp'
};

export class Address {
	peer_id;
	hostname = '';
	ports = { l: 443 };
	token;
	constructor() { Object.assign(this, ...arguments); }

	urls() {
		return Object.entries(this.ports).map(
			([key, port]) => `${proto[key]}:${this.hostname}:${port}${transport[key]}`
		);
	}
	username(local_id = pid) {
		const token = this.token || gen_token();
		return `${this.peer_id}.${local_id}.${token}`;
	}
	credential() {
		return 'the/turn/password/constant';
	}
	ice_pwd() {
		return 'the/ice/password/constant';
	}

	static from_string(s) {
		let [peer_id, hostname, ports_s, token] = s.split(',');
		peer_id = PeerId.from_string(peer_id);
		const reg = /([tlud])([0-9a-fA-F]{4})/g;
		const ports = {};
		let res;
		while (res = reg.exec(ports_s)) {
			const { 1: key, 2: port } = res;
			ports[key] = parseInt(port, 16);
		}

		return new this({ peer_id, hostname, ports, token });
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'string') {
			let ports = '';
			for (const [key, port] of Object.entries(this.ports)) {
				ports += key + port.toString(16).padStart(4, '0');
			}
			let ret = `${this.peer_id},${this.hostname},${ports}`;
			if (this.token) ret += ',' + this.token;
			return ret;
		}
		return;
	}
}
