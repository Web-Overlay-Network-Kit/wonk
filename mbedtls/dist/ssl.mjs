import {alloc_str, mbedtls, OomError, read_str, sizeof, imports, mem8} from './mbedtls.mjs';
// import {
// 	MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_IS_CLIENT,
// 	MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
// 	MBEDTLS_SSL_PRESET_DEFAULT
// } from './mbedtls_def.mjs';

const ssl_conns = new Map();
imports.ssl = {
	ssl_send(ptr, buff_ptr, len) { return ssl_conns.get(ptr).send(mem8(buff_ptr, len)); },
	ssl_recv(ptr, buff_ptr, len) { return ssl_conns.get(ptr).recv(mem8(buff_ptr, len)); },
	ssl_set_timer(ptr, a, b) { 
		const conn = ssl_conns.get(ptr);
		if (!conn) return; // set_timer_cb calls ssl_set_timer, except we haven't set the ptr into ssl_conns yet... but it's just a reset and we start resetted anyway so just skip it...
		return conn.set_timer(a, b);
	},
	ssl_get_timer(ptr) { return ssl_conns.get(ptr).get_timer(); }
};

export class SslConn {
	#inner;
	#reader;
	#writer;
	
	#ssl;

	#int = 0;
	#fin = 0;
	#timer_handle;

	readable = new ReadableStream(this);
	writable = new WritableStream(this);
	get remoteAddr() { return this.#inner.remoteAddr; }
	get localAddrr() { return this.#inner.localAddrr; }

	constructor(inner, { cert_chain, private_key, is_server = true, is_udp = false} = {}) {
		this.#inner = inner;
		this.#reader = this.#inner.readable.getReader();
		this.#writer = this.#inner.writable.getWriter();

		const cert_pem = alloc_str(cert_chain);
		const sk_pem = alloc_str(private_key);
		const client_id = alloc_str(Object.values(this.#inner.remoteAddr).join(''));

		if ([cert_pem, sk_pem].some(v => v == 0)) throw new OomError();

		this.#ssl = mbedtls.ssl_new(cert_pem, sk_pem, is_server, is_udp, client_id);
		if (!this.#ssl) throw new Error('failed to create Ssl');

		ssl_conns.set(this.#ssl, this);

		// Start running the handshake:
		this.#handshake();
	}
	free() {
		mbedtls.ssl_free(this.#ssl);
	}
	#handshake() {
		const ctx = mbedtls.ssl_ctx(this.#ssl);
		const res = mbedtls.mbedtls_ssl_handshake(ctx);
		// TODO: add a promise for handshake completion
		console.log('handshake', res);
	}

	send(buff) {
		debugger;
	}
	recv(buff) {
		debugger;
	}
	set_timer(int, fin) {
		if (this.#timer_handle) this.#timer_handle = clearTimeout(this.#timer_handle);

		if (!fin) { this.#fin = false; }

		const now = Date.now();
		this.#int = now + int;
		this.#fin = now + fin;
		this.#timer_handle = setTimeout(this.#handshake.bind(this), fin);
	}
	get_timer() {
		if (!this.#fin) return -1;
		
		const now = Date.now();
		if (now < this.#int) return 0;
		if (now < this.#fin) return 1;
		return 2;
	}

	async pull(controller) {

	}
	async write(chunk) {

	}
}
