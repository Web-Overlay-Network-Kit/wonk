use eyre::Result;

use std::{net::{TcpListener, TcpStream}, sync::Arc};

use mbedtls::{ssl::{Config, config::NullTerminatedStrList, Context}, x509::Certificate, pk::Pk};

fn handle_stream(config: Arc<Config>, conn: TcpStream) -> Result<()> {
	let mut ctx = Context::new(config);
	ctx.establish(conn, None)?;

	println!("alpn: {:?}", ctx.get_alpn_protocol());

	std::io::copy(&mut ctx, &mut std::io::stdout())?;

	Ok(())
}

fn main() -> Result<()> {
	let mut cert_pem = std::fs::read("./cert.pem")?;
	cert_pem.push(0); // mbedtls requires PEM to be null-terminated
	let mut pk_pem = std::fs::read("./pk.pem")?;
	pk_pem.push(0);
	let cert = Arc::new(Certificate::from_pem_multiple(&cert_pem)?);
	let pk = Arc::new(Pk::from_private_key(&pk_pem, None)?);

	let mut config = Config::new(mbedtls::ssl::config::Endpoint::Server, mbedtls::ssl::config::Transport::Stream, mbedtls::ssl::config::Preset::Default);
	config.push_cert(cert, pk)?;
	config.set_alpn_protocols(Arc::new(
		NullTerminatedStrList::new(&[
			"http 1.1",
			"h2",
			"stun.turn"
		])?
	))?;


	let config = Arc::new(config);


	for conn in TcpListener::bind("[::]:443")?.incoming().flatten() {
		let config = config.clone();
		std::thread::spawn(move || {
			if let Err(e) = handle_stream(config, conn) {
				println!("{e}");
			}
		});
	}

	Ok(())
}
