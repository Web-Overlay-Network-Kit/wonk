#include "mbedtls/platform.h"
#include "config.h"
#include "mbedtls/ssl.h"
// #include "mbedtls/ssl_cache.h"
// #include "mbedtls/ssl_cookie.h"
// #include "mbedtls/ssl_ticket.h"
// #include "mbedtls/timing.h"
// #include "mbedtls/pem.h"
// #include "mbedtls/x509.h"
// #include "mbedtls/x509_crt.h"

// Randomization:
__attribute__((import_module("mbedtls"), import_name("rng"))) int js_rng(void*, void* buff, size_t len);

__attribute__((import_module("mbedtls"), import_name("dbg"))) void js_dbg(void *, int, const char *, int, const char *);

int main() {
	// mbedtls_platform_set_time(get_time);
	return 0;
}
