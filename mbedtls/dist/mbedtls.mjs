export const imports = {
	mbedtls: {
		random(ptr, len) {
			crypto.getRandomValues(mem8(ptr, len));
		}
	}
};

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export let mbedtls;

export class OomError extends Error {
	constructor() {
		super("The WASM module ran out of memory.");
	}
}

export function mem8(offset, length) {
	return new Uint8Array(mbedtls.memory.buffer, offset, length);
}
export function memdv(offset, length) {
	return new DataView(mbedtls.memory.buffer, offset, length);
}

export function alloc_str(s) {
	if (!s.endsWith('\0')) {
		s += '\0';
	}
	const encoded = encoder.encode(s);

	const ptr = mbedtls.malloc(encoded.byteLength);
	if (!ptr) return;

	mem8(ptr, encoded.byteLength).set(encoded);

	return ptr;
}
export function read_str(ptr, len = mbedtls.strlen(ptr)) {
	return decoder.decode(mem8(ptr, len));
}

const struct_names = [
	'mbedtls_pem_context',
	'mbedtls_pk_context',
	'mbedtls_ssl_cache_context',
	'mbedtls_ssl_config',
	'mbedtls_ssl_context',
	'mbedtls_ssl_cookie_ctx',
	'mbedtls_ssl_session',
	'mbedtls_ssl_ticket_context',
	'mbedtls_ssl_ticket_key',
	'mbedtls_timing_delay_context',
	'mbedtls_x509_authority',
	'mbedtls_x509_crt',
	'mbedtls_x509write_cert',
	
];
export function sizeof(struct_name) {
	return mbedtls.sizeof(struct_names.indexOf(struct_name))
}

export const init = (async function init_mbedtls() {
	const compiled_module = await WebAssembly.compileStreaming(await fetch(new URL('mbedtls.wasm', import.meta.url)));
	
	// Wrap the imports.  This way we only have to actually define the imports which we end up using.
	const wrapped_imports = {};
	for (const {module, name, kind} of WebAssembly.Module.imports(compiled_module)) {
		wrapped_imports[module] ??= {};

		if (kind !== 'function') {
			wrapped_imports[module][name] = imports[module][name];
			continue;
		}

		wrapped_imports[module][name] = function import_wrapper() {
			return imports[module][name](...arguments);
		};
	}

	const instance = await WebAssembly.instantiate(compiled_module, wrapped_imports);

	mbedtls = instance.exports;
	
	mbedtls._start();
})();
