import { UdpListener } from "./index.mjs";

const udp = await Deno.listenDatagram({ port: 4666, transport: 'udp' });
console.log(udp.addr, udp);

// for await (const [data, addr] of udp) {
// 	console.log(addr, data);
// }

for await (const conn of new UdpListener(udp)) {
	conn.readable.pipeTo(conn.writable);
	// (async () => {
	// 	for await (const [data, addr] of conn) {
	// 		console.log(addr, data);
	// 	}
	// })();
}
