

const listener = Deno.listenTls({ port: 443, certFile: 'cert.pem', keyFile: 'pk.pem' });
// const listener = Deno.listen({ port: 80 });

import { Turn } from './turn.mjs';

for await (const conn of listener) {
	// Spawn a task per connection:
	(async () => {
		try {
			const writer = conn.writable.getWriter();
			for await(const packet of Turn.parse_readable(conn.readable)) {
				console.log("<-", conn.remoteAddr, packet.length);
				if (packet.length > 100) {
					debugger;
					console.log(packet.attributes);
				}
	
				packet.length = 0;
				packet.class = 3;
				packet.set_realm("realm");
				packet.set_nonce("nonce");
				packet.set_error(401, "");
	
				// console.log("->", packet.packet.);
	
				await writer.ready;
				await writer.write(packet.packet);
			};
		} catch {}
	})();
}
