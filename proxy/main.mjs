

const listener = Deno.listenTls({ port: 443, certFile: 'cert.pem', keyFile: 'pk.pem' });

import { Turn } from './turn.mjs';

for await (const conn of listener) {
	// Spawn a task per connection:
	(async () => {
		for await(const packet of Turn.parse_readable(conn.readable)) {
			debugger;
			console.log(conn.remoteAddr, packet);
		};
	})();
}
