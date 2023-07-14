import { UdpListener } from 'wonk-net';
import { init, SslConn } from 'wonk-mbedtls';

const cert_chain = await Deno.readTextFile('cert.pem');
const private_key = await Deno.readTextFile('pk.pem');

await init;

const udp = await Deno.listenDatagram({ port: 4666, transport: 'udp' });
console.log(udp.addr, udp);

// for await (const [data, addr] of udp) {
// 	console.log(addr, data);
// }

for await (const conn of new UdpListener(udp)) {
	const ssl_conn = new SslConn(conn, { cert_chain, private_key, is_server: true, is_udp: true });
	ssl_conn.readable.pipeTo(ssl_conn.writable);
	// conn.readable.pipeTo(conn.writable);
	// (async () => {
	// 	for await (const [data, addr] of conn) {
	// 		console.log(addr, data);
	// 	}
	// })();
}
