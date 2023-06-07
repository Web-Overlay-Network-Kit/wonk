#ifndef TIMING_ALT_H
#define TIMING_ALT_H

typedef struct mbedtls_timing_hr_time {
	double x;
} mbedtls_timing_hr_time;

typedef struct mbedtls_timing_delay_context {
	double interval_ms;
	double final_ms;
} mbedtls_timing_delay_context;

#endif
