export default async function init({sub_modules = [
	'rsa',
	'ecdsa',
	'ssl'
]}) {

	const module = await WebAssembly.compileStreaming(await fetch(new URL('./mbedtls.wasm', import.meta.url)));
	const imports = {};
	for (const entry in WebAssembly.Module.imports(module)) {

	}

	const {instance} = await WebAssembly.instantiate(module, imports);

	return instance.exports;
}
