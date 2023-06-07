#include "mbedtls/platform.h"
#include "config.h"

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
	get_random(output, len);
	*olen = len;
	return 0;
}

int main() {
	mbedtls_platform_set_time(get_time);
	return 0;
}
