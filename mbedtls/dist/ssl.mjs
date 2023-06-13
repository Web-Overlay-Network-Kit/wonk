import {alloc_str, mbedtls, OomError, read_str, sizeof} from './mbedtls.mjs';
import {
	MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_IS_CLIENT,
	MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
	MBEDTLS_SSL_PRESET_DEFAULT
} from './mbedtls_def.mjs';

export class TlsProtocol {
	#sk;
	#cert;
	#conf;
	#ctx;
	// Try to match the interface for Deno.listenTls:
	constructor({certChain, privateKey, is_server = true} = {}) {
		// Should I combine this into a single malloc?
		this.#ctx = mbedtls.malloc(sizeof('mbedtls_ssl_context'));
		this.#conf = mbedtls.malloc(sizeof('mbedtls_ssl_config'));
		this.#cert = mbedtls.malloc(sizeof('mbedtls_x509_crt'));
		this.#sk = mbedtls.malloc(sizeof('mbedtls_pk_context')); // Secret Key / Private Key
		const cert_pem = alloc_str(certChain);
		const sk_pem = alloc_str(privateKey);
		
		try {
			if ([this.#ctx, this.#conf, this.#cert, this.#sk, cert_pem, sk_pem].indexOf(0) != -1) throw new OomError();

			// Initialize the objects:
			mbedtls.mbedtls_ssl_init(this.#ctx);
			mbedtls.mbedtls_ssl_config_init(this.#conf);
			mbedtls.mbedtls_x509_crt_init(this.#cert);
			mbedtls.mbedtls_pk_init(this.#sk);

			// Parse the certificate chain:
			let res = mbedtls.mbedtls_x509_crt_parse(this.#cert, cert_pem, mbedtls.strlen(cert_pem) + 1);
			if (res !== 0) throw new Error("Failed to parse the cert chain.");

			// Parse the secret key:
			res = mbedtls.mbedtls_pk_parse_key(
				this.#sk,
				sk_pem, mbedtls.strlen(sk_pem) + 1,
				0, 0,
				mbedtls.f_rng()
			);
			if (res != 0) throw new Error("Failed to parse the private key / secret key.");

			// Setup the configuration:
			res = mbedtls.mbedtls_ssl_config_defaults(this.#conf,
				is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT
			);
			if (res != 0) throw new Error('Failed to set the defaults on the ssl config.');

			mbedtls.mbedtls_ssl_conf_rng(this.#conf, mbedtls.f_rng(), 0);

			res = mbedtls.mbedtls_ssl_conf_own_cert(this.#conf, this.#cert, this.#sk);
			if (res != 0) throw new Error('Failed to set the certificate on the ssl config.');

			// Setup the SSL context:
			res = mbedtls.mbedtls_ssl_setup(this.#ctx, this.#conf);
			if (res != 0) throw new Error('Failed to set the configuration on the ssl context.');
		} catch (e) {
			this.free();
			throw e;
		} finally {
			mbedtls.free(cert_pem);
			mbedtls.free(sk_pem);
		}
	}
	free() {
		mbedtls.mbedtls_ssl_free(this.#ctx);
		mbedtls.mbedtls_ssl_config_free(this.#conf);
		mbedtls.mbedtls_x509_crt_free(this.#cert);
		mbedtls.mbedtls_pk_context_free(this.#sk);
	}
}
