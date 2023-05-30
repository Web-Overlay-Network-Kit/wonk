// It's ok to use top-level await here, because this library can only be used in pages (since we need RTCPeerConnection which doesn't exist inside workers)
import './identity.mjs';


export default class PeerCon extends RTCPeerConnection {
	
}
