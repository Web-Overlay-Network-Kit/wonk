import { btoa_url } from "./b64url.mjs";
import { OwnPeerId } from "./peerid.mjs";

const db_req = indexedDB.open('identity.mjs', 1);
db_req.onupgradeneeded = ({ target: { result: db }}) => {
	db.createObjectStore('cert', {keyPath: 'fingerprint'});
};
const db = await new Promise((res, rej) => {
	db_req.onerror = () => rej(db_req.error);
	db_req.onsuccess = () => res(db_req.result);
});

// Generate an RTCCertificate (We do this upfront because it's async so we can't do it inside an indexeddb transaction, and I think the alternative is to either use IndexedDB to build an async lock or to use the WebLocks api.  This is unneccessary work but it only happens on import so, I'm content with it.)
const candidate = await RTCPeerConnection.generateCertificate({
	// More info on the options for the cert: https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-generatecertificate
	name: 'ECDSA',
	namedCurve: 'P-256'
});

const own = await OwnPeerId.from_cert(candidate);
console.log(own);
console.log(String(own), BigInt(own));


// Slap a fingerprint on the cert
if (false && typeof candidate.getFingerprints == 'function') {
	for (const {algorithm, value} of candidate.getFingerprints()) {
		if (algorithm == 'sha-256') {
			candidate.fingerprint = btoa_url(
				value.split(':')
				.map(s => parseInt(s, 16))
				.reduce((a, n) => a + String.fromCharCode(n))
			);
		}
	}
}

// If that didn't work, then use a temporary connection to get the fingerprint:
if (!candidate.fingerprint) {
	const temp = new RTCPeerConnection({ certificates: [candidate] });
	const _dc = temp.createDataChannel('');
	const offer = await temp.createOffer();
	console.log(offer.sdp);

	let res;
	let exp = /a=fingerprint:(sha-256) ([\d[a-fA-F]{2}(?::[\da-fA-F]{2})*)/g;
	while (res = exp.exec(offer.sdp)) {
		const {1: algorithm, 2: value} = res;
		if (algorithm == 'sha-256') {
			candidate.fingerprint = btoa_url(
				value.split(':')
				.map(s => parseInt(s, 16))
				.reduce((a, n) => a + String.fromCharCode(n))
			);
		}
	}
	temp.close();
}

console.log(candidate)

// Get or set the certificate inside indexeddb:
const trans = db.transaction('cert', 'readwrite');


console.log(candidate);
