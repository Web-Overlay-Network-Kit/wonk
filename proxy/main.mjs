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
	// TURN Send Indication
	else if (turn.class == 1 && turn.method == 0x006) {
		// console.log(turn.xpeer, turn.data);
		const data = turn.data;
		const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
		if (view.byteLength < 1) continue;

		listener.send(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), { hostname: "localhost", port: 4666 });

		const first_byte = view.getUint8(0);
		
		// STUN:
		if (first_byte < 4) {
			const inner = Turn.parse_packet(view);
			console.log('ct', inner);
			if (inner.class == 0 && inner.method == 1 && await inner.check_auth(cm)) {
				const ct_res = new Stun();
				ct_res.class = 2;
				ct_res.method = inner.method;
				ct_res.txid = inner.txid;
				ct_res.xmapped = addr;
				// ct_res.username = inner.username;
				await ct_res.auth(cm, inner.username);

				listener.send(ct_res.packet, { hostname: "localhost", port: 6742 });
	
				// debugger;
	
				res.class = 1;
				crypto.getRandomValues(res.txid_buf);
				res.method = 0x007; // Data Indication
				res.xpeer = turn.xpeer;
				res.data = ct_res.packet;
			} else {
				continue;
			}
		}
		//DTLS
		else if (20 <= first_byte && first_byte < 64) {
			// TODO: Froward the packet to the other side?
		}
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
