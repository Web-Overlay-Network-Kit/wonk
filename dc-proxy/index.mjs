// Wrapper for a datachannel that is running "somewhere else"

export class DcProxy extends EventTarget {
	#inner;
	#bufferedThreshold = 0;
	
	label = '';
	protocol = '';

	ordered = true;

	async get_readyState() {}
	async get_bufferedAmount() {}
	get bufferedAmountLowThreshold() { return this.#bufferedThreshold; }
	set bufferedAmountLowThreshold(_) {}

	constructor(inner, options = {}) {
		this.#inner = inner;
		Object.assign(this, options);
	}

	async close() {}
	send() {}
}

export function proxy_dc(dc) {
	const { port1: theirs, port2: ours } = new MessageChannel();

	ours.onmessage = async function handler() {};
	dc.addEventListener('open', () => {});
	dc.addEventListener('message', () => {});
	dc.addEventListener('error', () => {});
	dc.addEventListener('closing', () => {});
	dc.addEventListener('close', () => {});
	dc.addEventListener('bufferedamountlow', () => {});

	return theirs;
}
