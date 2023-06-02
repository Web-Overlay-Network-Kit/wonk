import { PeerId } from 'wonk-peerid';
import { cert, pid } from 'wonk-identity';

// RTC configuration that will be used when creating connections:
export const rtc_config = {
	certificates: [cert],
	iceCandidatePoolSize: 4,
	iceServers: [
		{ urls: 'stun:global.stun.twilio.com:3478' },
		{ urls: 'stun:stun.l.google.com:19302' }
	],
	peerIdentity: null,
	rtcpMuxPolicy: 'require'
};

function encode_candidates(candidates) {
	// TODO: Firefox doesn't have address/port/type on RTCIceCandidate - it only has .candidate which means we have to parse it manually.
	return candidates.map(c => `${c.type.substr(0, 1)}${c.port.toString(16).padStart(4, '0')}${c.address}`).join(',');
}
function decode_candidates(s) {
	return decodeURIComponent(s).split(',').map((s, i) => {
		const type = ['host', 'srflx', 'relay'].find(t => t.startsWith(s.substring(0, 1)));
		const port = parseInt(s.substring(1, 4), 16);
		const address = s.substring(5);
		
		return new RTCIceCandidate({
			candidate: `candidate:foundation 1 udp ${i + 1} ${address} ${port} typ ${type}`,
			sdpMLineIndex: 0
		});
	});
}

// TODO: Rename
export class SigMsg {
	id;
	ice_ufrag;
	ice_pwd;
	ice_candidates;
	constructor() { Object.assign(this, ...arguments); }
	static from_string(s) {
		let { 1: id, 2: ice_ufrag, 3: ice_pwd, 4: ice_candidates} = /([^.]+)\.([^.]+)\.([^.]+)\.(.+)/.exec(s);
		id = PeerId.from_string(id);
		ice_ufrag = ice_ufrag.replaceAll('-', '+').replaceAll('_', '/');
		ice_pwd = ice_pwd.replaceAll('-', '+').replaceAll('_', '/');
		ice_candidates = decode_candidates(decodeURIComponent(ice_candidates));
		return new this({id, ice_ufrag, ice_pwd, ice_candidates});
	}
	[Symbol.toPrimitive](_hint) {
		console.log(this.ice_candidates);
		const ice_candidates = this.ice_candidates.filter(c => c.protocol.toLowerCase() == 'udp').sort((a, b) => b.priority - a.priority);
		const candidates = encode_candidates(ice_candidates);

		return `${String(this.id)}.${
			this.ice_ufrag.replaceAll('+', '-').replaceAll('/', '_')
		}.${
			this.ice_pwd.replaceAll('+', '-').replaceAll('/', '_')
		}.${candidates}`;
	}
}
class SigEvent extends CustomEvent {
	msg;
	constructor(msg) {
		super('signaling');
		this.msg = msg;
	}
}

export class PeerCon extends RTCPeerConnection {
	// The 0 datachannel is used to determine when the connection has succeeded.  Once openned, it is used to renegotiate the connection.
	#dc;
	peer_id;
	#local_id;
	#remote_msg_res;
	#remote_msg = new Promise(res => this.#remote_msg_res = res);
	get signal_msg() {
		return this.#remote_msg;
	}
	set signal_msg(remote_msg) {
		this.#remote_msg_res(remote_msg);
	}
	constructor({config = rtc_config, local_id = pid} = {}) {
		super(config);
		this.#local_id = local_id;

		this.#dc = this.createDataChannel('_', {
			negotiated: true,
			id: 0
		});

		// Spawn the signalling / renegotiation task:
		this.#signaling_task();
	}
	async #signaling_task() {
		const ice_candidates = [];
		const ice_complete = new Promise(res => {
			const handler = ({ candidate }) => {
				if (candidate === null) {
					this.removeEventListener('icecandidate', handler);
					res();
				} else {
					ice_candidates.push(candidate);
				}
			};
			this.addEventListener('icecandidate', handler);
		});
		const connected = new Promise((res, rej) => {
			this.#dc.addEventListener('open', res, {once: true});
			this.#dc.addEventListener('error', rej, {once: true});
			this.#dc.addEventListener('closing', rej, {once: true});
		});

		await this.setLocalDescription();
		await ice_complete;

		const { 1: ice_ufrag } = /a=ice-ufrag:(.+)/.exec(this.localDescription.sdp);
		const { 1: ice_pwd } = /a=ice-pwd:(.+)/.exec(this.localDescription.sdp);
		const l_msg = new SigMsg({
			id: this.#local_id,
			ice_candidates,
			ice_ufrag,
			ice_pwd
		});
		this.dispatchEvent(new SigEvent(l_msg));

		// Wait for the other peer's signalling message to reach us:
		const r_msg = await this.signal_msg;
		this.peer_id = r_msg.id;

		const polite = this.#local_id.polite(this.peer_id);

		// Set the remote description:
		let sdp = `v=0
o=- 20 0 IN IP4 0.0.0.0
s=-
t=0 0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:${r_msg.ice_ufrag}
a=ice-pwd:${r_msg.ice_pwd}
a=setup:${polite ? 'active' : 'passive'}
a=sctp-port:5000
`;
		sdp += this.peer_id.sdp();
		console.log(sdp);
		await this.setRemoteDescription({ type: 'answer', sdp });
		for (const candidate of r_msg.ice_candidates) {
			this.addIceCandidate(candidate);
		}

		await connected;
		console.log('Connected.');

		// Handle renegotiation using the perfect negotiation pattern:
		// TODO:
	}
}
