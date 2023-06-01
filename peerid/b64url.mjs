export function btoa_url(b) {
	return btoa(b)
		.replaceAll('+', '-')
		.replaceAll('/', '_')
		.replaceAll('=', '');
}
export function atob_url(s) {
	s = s.replaceAll('-', '+')
		.replaceAll('_', '/');
	while (s.length % 4) s += '=';
	return atob(s);
}

export function buftobinstr(buffer) {
	if (buffer instanceof ArrayBuffer) {
		buffer = new Uint8Array(buffer);
	}
	if (!ArrayBuffer.isView(buffer)) throw new Error("Can't convert this into a buffer: ", buffer);
	if (!(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

	return buffer.reduce((a, v) => a + String.fromCharCode(v), '');
}
export function binstrtobuf(binstr) {
	const ret = new Uint8Array(binstr.length);
	
	return new Uint8Array(binstr.split('').map(s => s.charCodeAt(0)));
}
