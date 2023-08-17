import { PeerId } from 'wonk-peerid';
import { cert, pid } from 'wonk-identity';
export { Address } from './address.mjs';

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
		const port = parseInt(s.substring(1, 5), 16);
		const address = s.substring(5);
		
		return new RTCIceCandidate({
			candidate: `candidate:foundation 1 udp ${i + 1} ${address} ${port} typ ${type}`,
			sdpMLineIndex: 0
		});
	});
}

function gen_candidate() {
	// Give tasty treats to the US DoD:
	const rand = crypto.getRandomValues(new Uint8Array(2 + 3));
	return decode_candidates(`h${rand[0].toString(16).padStart(2, '0')}${rand[1].toString(16).padStart(2, '0')}30.${rand[2]}.${rand[3]}.${rand[4]}`);
}

export class SigMsg {
	id;
	ice_ufrag;
	ice_pwd;
	ice_candidates;
	constructor(arg) {
		function decode(s) {
			let { 1: id, 2: ice_ufrag, 3: ice_pwd, 4: ice_candidates} = /([^.]+)\.([^.]+)\.([^.]+)\.(.+)/.exec(s);
			id = new PeerId(id);
			ice_ufrag = ice_ufrag.replaceAll('-', '+').replaceAll('_', '/');
			ice_pwd = ice_pwd.replaceAll('-', '+').replaceAll('_', '/');
			ice_candidates = decode_candidates(decodeURIComponent(ice_candidates));
			return { id, ice_ufrag, ice_pwd, ice_candidates };
		}
		const { id, ice_ufrag, ice_pwd, ice_candidates } = (typeof arg == 'string') ? decode(arg) : arg;
		this.id = id;
		this.ice_ufrag = ice_ufrag;
		this.ice_pwd = ice_pwd;
		this.ice_candidates = ice_candidates;
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

export class PeerCon extends RTCPeerConnection {
	// The 0 datachannel is used to determine when the connection has succeeded.  Once openned, it is used to renegotiate the connection.
	#dc;
	peer_id;
	#local_id;

	#remote_msg_res;
	#remote_msg = new Promise(res => this.#remote_msg_res = res);
	set remote_msg(msg) {
		if (!(msg instanceof SigMsg)) msg = new SigMsg(msg);
		this.#remote_msg_res(msg);
	}
	get remote_msg() {
		return this.#remote_msg;
	}
	#local_msg_res;
	local_msg = new Promise(res => this.#local_msg_res = res);
	#local_ice_cred_res;
	local_ice_cred = new Promise(res => this.#local_ice_cred_res = res);

	constructor({config = rtc_config, local_id = pid} = {}) {
		super(config);
		this.#local_id = local_id;

		this.#dc = this.createDataChannel('_', {
			negotiated: true,
			id: 0
		});

		// Spawn the signalling / renegotiation task:
		this.#signaling_task()
			.catch(() => {}); // Don't leave the promise uncaught
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

		// TODO: Also take into consideration the RTCPeerConnection.connectionState
		this.connected = new Promise((res, rej) => {
			this.#dc.addEventListener('open', res, {once: true});
			this.#dc.addEventListener('error', rej, {once: true});
			this.#dc.addEventListener('closing', rej, {once: true});
			this.addEventListener('connectionstatechange', e => {
				if (this.connectionState == 'failed' || this.connectionState == 'closed') {
					rej(e);
				}
			});
		});
		this.connected.catch(() => { this.close(); });

		await this.setLocalDescription();
		
		const { 1: ice_ufrag } = /a=ice-ufrag:(.+)/.exec(this.localDescription.sdp);
		const { 1: ice_pwd } = /a=ice-pwd:(.+)/.exec(this.localDescription.sdp);
		this.#local_ice_cred_res({ ice_ufrag, ice_pwd });

		ice_complete.then(() => {
			const l_msg = new SigMsg({
				id: this.#local_id,
				ice_candidates,
				ice_ufrag,
				ice_pwd
			});
			this.#local_msg_res(l_msg);
		});


		// Wait for the other peer's signalling message to reach us:
		const r_msg = await this.remote_msg;
		this.peer_id = r_msg.id;

		const polite = this.#local_id.polite(this.peer_id);
		
		// Spawn the perfect negotiation handler:
		this.perfect(polite);

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
		await this.setRemoteDescription({ type: 'answer', sdp });
		for (const candidate of r_msg.ice_candidates) {
			await this.addIceCandidate(candidate);
		}
	}
	// The perfect negotiation pattern, signalled over the 0 datachannel:
	perfect(polite) {
		let making_offer = false;
		let ignore_offer = false;
		this.addEventListener('negotiationneeded', async () => {
			await this.connected;
			try {
				making_offer = true;
				await this.setLocalDescription();
				this.#dc.send(JSON.stringify({
					description: this.localDescription
				}));
			} catch (e) {
				console.error(e);
			} finally {
				making_offer = false;
			}
		});
		this.addEventListener('icecandidate', async ({ candidate }) => {
			await this.connected;
			this.#dc.send(JSON.stringify({ candidate }));
		});
		this.#dc.addEventListener('message', async ({ data }) => {
			if (typeof data != 'string') return;
			let msg;
			try { msg = JSON.parse(data); } catch { return; };
			if (typeof msg != 'object') return;
			const { description, candidate } = msg ?? {};
			try {
				if (description) {
					const offer_collision = description.type === 'offer' &&
					(making_offer || this.signalingState != 'stable');

					ignore_offer = !polite && offer_collision;
					if (ignore_offer) return;

					await this.setRemoteDescription(description);
					if (description.type == 'offer') {
						await this.setLocalDescription();
						this.#dc.send(JSON.stringify({ description: this.localDescription }));
					}
				}
				if (candidate) {
					try {
						await this.addIceCandidate(candidate);
					} catch (e) {
						if (!ignore_offer) throw e;
					}
				}
			} catch (e) {
				console.error(e);
			}
		});
	}
	static connect_address(address, {
		local_id = pid,
		config = rtc_config,
	} = {}) {
		const temp_config = Object.create(config);
		temp_config.iceServers = [
			{ urls: address.urls, username: address.username(local_id), credential: address.credential }
		];
		temp_config.iceTransportPolicy = 'relay';

		const conn = new this({ config: temp_config, local_id });

		// local_msg waits until ice gathering has completed, which can take a very long time.  We only really need the local ice_pwd which can be ready as soon as setLocalDescription has been called.
		conn.local_ice_cred.then(({ice_pwd}) => {
			conn.remote_msg = new SigMsg({
				id: address.peer_id,
				ice_ufrag: ice_pwd,
				ice_pwd: address.ice_pwd,
				ice_candidates: gen_candidate()
			});
		});

		// Once we're connected, then set the actual configuration and restart ICE:
		conn.connected.then(() => {
			conn.setConfiguration(config);
			conn.restartIce();
		}).catch(() => {});

		return conn;
	}
}
