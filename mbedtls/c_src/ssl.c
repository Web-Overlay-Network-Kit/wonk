#include <string.h>
#include "mbedtls/platform.h"
#include "config.h"
#include "mbedtls/ssl.h"
// #include "mbedtls/ssl_cache.h"
// #include "mbedtls/ssl_cookie.h"
// #include "mbedtls/ssl_ticket.h"
// #include "mbedtls/timing.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

extern int js_rng(void* _, unsigned char * buff, size_t bufflen);
extern void js_dbg(void *, int, const char *, int, const char *);

__attribute__((import_module("ssl"), import_name("ssl_send"))) int ssl_send(void *, const unsigned char *, size_t);
__attribute__((import_module("ssl"), import_name("ssl_recv"))) int ssl_recv(void *, unsigned char *, size_t);
__attribute__((import_module("ssl"), import_name("ssl_timer_set"))) void ssl_timer_set(void *, uint32_t, uint32_t);
__attribute__((import_module("ssl"), import_name("ssl_timer_get"))) int ssl_timer_get(void *);

typedef struct Ssl {
	mbedtls_ssl_context ctx;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt crt;
	mbedtls_pk_context sk;
} Ssl;

__attribute__((export_name("ssl_new"))) Ssl* ssl_new(unsigned char* cert_pem, unsigned char* sk_pem, char is_server, char is_udp, const char* client_id) {
	Ssl* ret = (Ssl*) malloc(sizeof(Ssl));
	if (ret == NULL) return NULL;

	// Cert
	mbedtls_x509_crt_init(&ret->crt);
	if (mbedtls_x509_crt_parse(&ret->crt, cert_pem, strlen(cert_pem) + 1) != 0) goto cleanup;

	// Secret Key
	mbedtls_pk_init(&ret->sk);
	if (mbedtls_pk_parse_key(&ret->sk, sk_pem, strlen(sk_pem) + 1, 0, 0, js_rng, 0) != 0) goto cleanup2;

	// Config
	mbedtls_ssl_config_init(&ret->conf);
	if (mbedtls_ssl_config_defaults(
		&ret->conf,
		is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
		is_udp ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) goto cleanup3;
	if (mbedtls_ssl_conf_own_cert(&ret->conf, &ret->crt, &ret->sk) != 0) goto cleanup3;
	mbedtls_ssl_conf_rng(&ret->conf, js_rng, 0);
	mbedtls_ssl_conf_dbg(&ret->conf, js_dbg, 0);

	// Context
	mbedtls_ssl_init(&ret->ctx);
	if (mbedtls_ssl_setup(&ret->ctx, &ret->conf) != 0) goto cleanup4;
	if (mbedtls_ssl_set_client_transport_id(&ret->ctx, client_id, strlen(client_id)) != 0) goto cleanup4;
	mbedtls_ssl_set_bio(&ret->ctx, ret, ssl_send, ssl_recv, 0);
	mbedtls_ssl_set_timer_cb(&ret->ctx, ret, ssl_timer_set, ssl_timer_get);

	return ret;

	// Cleanup
	cleanup4:
	mbedtls_ssl_free(&ret->ctx);
	cleanup3:
	mbedtls_ssl_config_free(&ret->conf);
	cleanup2:
	mbedtls_pk_free(&ret->sk);
	cleanup1:
	mbedtls_x509_crt_free(&ret->crt);
	cleanup:
	free(ret);
	return NULL;
}

__attribute__((export_name("ssl_ctx"))) mbedtls_ssl_context* ssl_ctx(Ssl* this) {
	return &this->ctx;
}

__attribute__((export_name("ssl_free"))) void ssl_free(Ssl* this) {
	mbedtls_ssl_free(&this->ctx);
	mbedtls_ssl_config_free(&this->conf);
	mbedtls_pk_free(&this->sk);
	mbedtls_x509_crt_free(&this->crt);
	free(this);
}
