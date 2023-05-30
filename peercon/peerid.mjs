import { buftobinstr, btoa_url, binstrtobuf, atob_url } from "./b64url.mjs";

const untagged = new Map();
// untagged.set(20, 'sha-1');
untagged.set(32, 'sha-256');
// untagged.set(48, 'sha-284');
untagged.set(64, 'sha-512');

export const advanced_usage = {
	id_fingerprint: 'sha-256',
	subtle_digests: [
		'SHA-1',
		'SHA-256', // Probably will never be used, because the browser generates these automatically.
		'SHA-384',
		'SHA-512'
	]
};

export class PeerId {
	fingerprints; // associative array: fingerprint-name -> binstr
	constructor() {
		Object.assign(this, ...arguments);
		if (!(advanced_usage.id_fingerprint in this.fingerprints)) {
			throw new Error("You must at least have the id_fingerprint inside your fingerprints.");
		}
	}

	// Parse a PeerId
	static from(encoded) {
		const fingerprints = Object.create(null);

		const parts = decodeURIComponent(encoded).split('|');
		if (parts.length < 1) throw new Error('Not a PeerId');

		// TODO: Support multiple fingerprints?
		const value = atob_url(parts.shift());
		const alg = (parts.length > 0) ? parts.shift() : untagged.get(value.length);
		if (!alg) throw new Error("Didn't recognize this untagged PeerId");
		if (alg != advanced_usage.id_fingerprint) throw new Error("This PeerId didn't include the id_fingerprint.");
		fingerprints[alg] = value;

		return new this({fingerprints});
	}
	// Return the sdp text for this PeerId:
	sdp() {
		const ret = '';
		for (const alg in this.fingerprints) {
			ret += `a=fingerprint:${alg} ${
				this.fingerprints[alg]
				.split('')
				.map(b => parseInt(b.charCodeAt(0)).toString(16).padStart(2, '0'))
				.join(':')
			}\n`;
		}
		return ret;
	}

	// toPrimitive converts the advanced_usage.id_fingerprint into either a BigInt or a String
	[Symbol.toPrimitive](hint) {
		if (!(advanced_usage.id_fingerprint in this.fingerprints)) return false;

		if (hint == 'number') {
			let agg = '0x';
			for (const b of binstrtobuf(this.fingerprints[advanced_usage.id_fingerprint])) {
				agg += b.toString(16).padStart(2, '0');
			}
			return BigInt(agg);
		}
		else {
			let ret = btoa_url(this.fingerprints[advanced_usage.id_fingerprint]);
			// Append the hash algorithm if it's not an untagged alg
			if (![...untagged.values()].includes(advanced_usage.id_fingerprint)) {
				ret += '|';
				ret += advanced_usage.id_fingerprint;
			}
			return encodeURIComponent(ret);
		}
	}
}

export class OwnPeerId extends PeerId {
	cert_chain;
	constructor() { super(...arguments); }

	// Are we the polite peer?
	polite(other_peerid) {
		this < other_peerid;
	}
	static async from_cert(cert) {
		// We use a temporary connection to pull information from this cert:
		const a = new RTCPeerConnection({ certificates: [cert] });
		const b = new RTCPeerConnection();
		const dc = a.createDataChannel('_');
		const done = new Promise((res, rej) => {
			dc.addEventListener('open', res);
			dc.addEventListener('error', rej);
		});

		// Candidates:
		a.onicecandidate = async ({candidate}) => b.addIceCandidate(candidate);
		b.onicecandidate = async ({candidate}) => a.addIceCandidate(candidate);

		// Signalling:
		await a.setLocalDescription();
		await b.setRemoteDescription(a.localDescription);
		await b.setLocalDescription();
		await a.setRemoteDescription(b.localDescription);

		// Wait for the datachannel to open:
		await done;

		// Pull the raw certificate chain from the RTCDtlsTransport (currently only works in Chrome):
		const cert_chain = (b?.sctp?.transport?.getRemoteCertificates ?? function(){return false;})();
		
		const fingerprints = Object.create(null);

		// Collect fingerprints from a.localDescription.sdp
		let reg = /a=fingerprint:([\w\d-]+) ([\da-fA-F]{2}(?::[\da-fA-F]{2})*)/g;
		let res;
		while (res = reg.exec(a.localDescription.sdp)) {
			const {1: algorithm, 2: value} = res;
			fingerprints[algorithm] = value
				.split(':')
				.map(s => parseInt(s, 16))
				.reduce((a, v) => a + String.fromCharCode(v), '');
		}

		// Collect fingerprints from subtle crypto using the raw cert chain:
		if (cert_chain) {
			for (const alg of advanced_usage.subtle_digests) {
				if (alg.toLowerCase() in fingerprints) continue;
				const buf = await crypto.subtle.digest(alg, cert_chain[0]);
				console.log('digest', alg, buf);
				fingerprints[alg.toLowerCase()] = buftobinstr(buf);
			}
		}

		a.close(); b.close();

		return new this({cert_chain, fingerprints});
	}
}
