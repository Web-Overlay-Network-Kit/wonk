import { OwnPeerId } from "wonk-peerid";

// Wrap Request
function wr(request) {
	return new Promise((res, rej) => {
		request.onerror = () => rej(request.error);
		request.onsuccess = () => res(request.result);
	});
}

// Open the database:
const db_req = indexedDB.open('wonk-identity', 1);
db_req.onupgradeneeded = ({ target: { result: db }}) => {
	db.createObjectStore('store');
};
const db = await wr(db_req);

// Generate an RTCCertificate (We do this upfront because it's async so we can't do it inside an indexeddb transaction, and I think the alternative is to either use IndexedDB to build an async lock or to use the WebLocks api.  This is unneccessary work but it only happens on import so, I'm content with it.)
const candidate_cert = await RTCPeerConnection.generateCertificate({
	// More info on the options for the cert: https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-generatecertificate
	// There're only two options: P256, and RSA 2048
	name: 'ECDSA',
	namedCurve: 'P-256'
});

const candidate_pid = await OwnPeerId.from_cert(candidate_cert);

// Exports:
export let cert;
export let pid;

// Get or set the certificate+pid inside indexeddb:
const trans = db.transaction('store', 'readwrite');
const store = trans.objectStore('store');
const existing = await wr(store.get(import.meta.url));
if (existing && existing.cert.expires > (Date.now() + 48 * 60 * 60 * 1000 /* 48hr */)) {
	cert = existing.cert;
	pid = new OwnPeerId(existing.pid);
} else {
	await wr(store.put({
		cert: candidate_cert,
		pid: candidate_pid
	}, import.meta.url));
	cert = candidate_cert;
	pid = candidate_pid;
}
trans.commit();

console.log('wonk-identity', pid, cert);
