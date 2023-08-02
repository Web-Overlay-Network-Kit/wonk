
const assocs = new Set();
export function* get_assocs(username, addr = false) {
	for (const assoc of assocs) {
		if (assoc.username !== username) continue;
		if (addr && (
			assoc.addr.hostname != addr.hostname ||
			assoc.addr.port != addr.port ||
			assoc.addr.transport != addr.transport
		)) continue;
		yield assoc;
	}
}
function other_username(username) {
	// Swap around the origin and destination
	const [dest, orig, token] = username.split('.');
	return [orig, dest, token].join('.');
}
export class Assoc {
	username;
	addr;
	#channels = new Map();
	async handle_turn(turn, addr) {

	}
	async forward(data, addr) {

	}
}
