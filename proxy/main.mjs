import { Turn } from './turn.mjs';

const listener = Deno.listenDatagram({ transport: 'udp', port: 4666 });

for await (const [packet, addr] of listener) {
	const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
	const turn = Turn.parse_packet(view);
	const attr = turn.attributes;
	turn.length = 0; // Clear the packet so that we can reuse it for the response
	
	console.log(addr, turn.class, turn.method);
	
	// STUN Binding Request:
	if (turn.class == 0 && turn.method == 1) {
		turn.class = 3;
		turn.set_addr(addr);
	}
	// Require authentication:
	else if (!attr.has('username')) {
		// Return a 401
		turn.class = 3;
		turn.set_nonce('nonce');
		turn.set_realm('realm');
		turn.set_error(401, '');
	}
	else { continue; }

	listener.send(turn.packet, addr);
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
