// Implement Listener for Deno's UDP 

function addr_to_str(addr) {
	return `${addr.transport}\0${addr.hostname}\0${addr.port}`;
}

export class UdpConn {
	#udp;
	readable;
	writable = new WritableStream(this);
	localAddr;
	remoteAddr;

	constructor(udp, ...rest) { this.#udp = udp; Object.assign(this, ...rest); }

	async write(chunk) {
		await this.#udp.send(chunk, this.remoteAddr);
	}
}

// Just a binding type thing
export class UdpListener {
	#inner;
	#conns = new Map(); // Addr(str) -> WritableStreamDefaultWriter
	addr;
	#waiters = [];
	constructor(inner) {
		this.#inner = inner;
		this.addr = this.#inner.addr;

		// Spawn the task:
		this.task();
	}
	async task() {
		for await (const [data, addr] of this.#inner) {
			const key = addr_to_str(addr);
			let writer = this.#conns.get(key);
			if (!writer) {
				const transform = new TransformStream();
				writer = transform.writable.getWriter();
				const readable = transform.readable;
				const conn = new UdpConn(this.#inner, { readable, localAddr: this.addr, remoteAddr: addr });
				this.#conns.set(key, conn);
				
				const waiter = this.#waiters.shift();
				if (waiter) waiter(conn);
			}

			await writer.write(data);
		}
	}
	accept() {
		return new Promise(res => {
			this.#waiters.push(res);
		});
	}
	async *[Symbol.asyncIterator]() {
		while (1) {
			yield await this.accept();
		}
	}
}
