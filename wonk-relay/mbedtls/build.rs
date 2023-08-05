use eyre::Result;

fn main() -> Result<()> {
	let mut files = Vec::new();
	for path in glob::glob("vendor/library/**/*.c")? {
		files.push(path?);
	}

	// TODO: Handle compiling to wasi when the target is wasm32?
	println!("cargo:rerun-if-changed=include/config.h");
	cc::Build::new()
		.files(files)
		.define("MBEDTLS_CONFIG", Some(r#""config.h""#))
		.include("include")
		.include("vendor/include")
		.include("vendor/library")

		.compile("mbedtls");

	println!("cargo:rustc-link-lib=mbedtls");

	println!("cargo:rerun-if-changed=include/bindgen.h");
	let bindings = bindgen::builder()
		.header("include/bindgen.h")
		.clang_args([
			"-Iinclude",
			"-Ivendor/include",
			"-Ivendor/library",
			r#"-DMBEDTLS_CONFIG="config.h""#
		])
		.parse_callbacks(Box::new(bindgen::CargoCallbacks))
		.constified_enum("mbedtls_md_type_t")
		.generate()?;
	bindings.write_to_file("src/bindings.rs")?;

	Ok(())
}
