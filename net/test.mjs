import { UdpListener } from "./index.mjs";
import { init, SslConn } from "../mbedtls/dist/ssl.mjs";

await init;

const udp = await Deno.listenDatagram({ port: 4666, transport: 'udp' });
console.log(udp.addr, udp);

// for await (const [data, addr] of udp) {
// 	console.log(addr, data);
// }

for await (const conn of new UdpListener(udp)) {
	const ssl_conn = new SslConn(conn, )
	conn.readable.pipeTo(conn.writable);
	// (async () => {
	// 	for await (const [data, addr] of conn) {
	// 		console.log(addr, data);
	// 	}
	// })();
}
