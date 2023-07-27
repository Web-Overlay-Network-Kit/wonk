import { Turn, Stun, CredentialManager } from './turn.mjs';

const listener = Deno.listenDatagram({ transport: 'udp', port: 3478 });

const cm = new CredentialManager();

for await (const [packet, addr] of listener) {
	const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
	const turn = Turn.parse_packet(view);

	const res = new Stun();
	res.method = turn.method;
	res.txid = turn.txid;

	// console.log(addr, turn.class, turn.method);
	
	// STUN Binding Request:
	if (turn.class == 0 && turn.method == 1) {
		res.class = 2;
		res.mapped = addr;
		res.xmapped = addr;
	}
	// Everything else requires authentication
	else if (turn.class == 0 && !await turn.check_auth(cm)) {
		res.class = 3;
		res.error = {code: 401};
		res.nonce = 'nonce';
		res.realm = 'realm';
	}
	// TURN Allocate
	else if (turn.class == 0 && turn.method == 3) {
		res.class = 2;
		res.username = turn.username;
		res.realm = 'realm';
		res.nonce = 'nonce';
		res.xrelay = addr; // TODO: If the transport is TCP, then we shouldn't use addr as the relayed address.
		res.xmapped = addr;
		res.lifetime = 3600;
		await res.auth(cm);
	}
	// Require authentication:
	// else if (!attr.has('username')) {
	// 	// Return a 401
	// 	turn.class = 3;
	// 	turn.nonce = 'nonce';
	// 	turn.realm = 'realm';
	// 	turn.error = {code: 401};
	// }
	else { continue; }

	await listener.send(res.packet, addr);
}


// const listener = Deno.listenTls({ port: 443, certFile: 'cert.pem', keyFile: 'pk.pem' });
// const listener = Deno.listen({ port: 80 });


// for await (const conn of listener) {
// 	// Spawn a task per connection:
// 	(async () => {
// 		try {
// 			const writer = conn.writable.getWriter();
// 			for await(const packet of Turn.parse_readable(conn.readable)) {
// 				console.log("<-", conn.remoteAddr, packet.length);
// 				if (packet.length > 100) {
// 					debugger;
// 					console.log(packet.attributes);
// 				}
	
// 				packet.length = 0;
// 				packet.class = 3;
// 				packet.set_realm("realm");
// 				packet.set_nonce("nonce");
// 				packet.set_error(401, "");
	
// 				// console.log("->", packet.packet.);
	
// 				await writer.ready;
// 				await writer.write(packet.packet);
// 			};
// 		} catch {}
// 	})();
// }
