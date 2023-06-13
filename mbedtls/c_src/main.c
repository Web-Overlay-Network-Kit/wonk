#include "mbedtls/platform.h"
#include "config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/timing.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

static const int sizes[] = {
	// sizeof(mbedtls_aes_context),
	// sizeof(mbedtls_aes_xts_context),
	// sizeof(mbedtls_aria_context),
	// sizeof(mbedtls_asn1_bitstring),
	// sizeof(mbedtls_asn1_buf),
	// sizeof(mbedtls_asn1_named_data),
	// sizeof(mbedtls_asn1_sequence),
	// sizeof(mbedtls_camellia_context),
	// sizeof(mbedtls_ccm_context),
	// sizeof(mbedtls_chacha20_context),
	// sizeof(mbedtls_chachapoly_context),
	// sizeof(mbedtls_cipher_context_t),
	// sizeof(mbedtls_cipher_info_t),
	// sizeof(mbedtls_cmac_context_t),
	// sizeof(mbedtls_ctr_drbg_context),
	// sizeof(mbedtls_des3_context),
	// sizeof(mbedtls_des_context),
	// sizeof(mbedtls_dhm_context),
	// sizeof(mbedtls_ecdh_context),
	// sizeof(mbedtls_ecdh_context_mbed),
	// sizeof(mbedtls_ecjpake_context),
	// sizeof(mbedtls_ecp_curve_info),
	// sizeof(mbedtls_ecp_group),
	// sizeof(mbedtls_ecp_keypair),
	// sizeof(mbedtls_ecp_point),
	// sizeof(mbedtls_entropy_context),
	// sizeof(mbedtls_entropy_source_state),
	// sizeof(mbedtls_error_pair_t),
	// sizeof(mbedtls_gcm_context),
	// sizeof(mbedtls_hmac_drbg_context),
	// sizeof(mbedtls_lmots_parameters_t),
	// sizeof(mbedtls_lmots_public_t),
	// sizeof(mbedtls_lms_parameters_t),
	// sizeof(mbedtls_lms_public_t),
	// sizeof(mbedtls_md5_context),
	// sizeof(mbedtls_md_context_t),
	// sizeof(mbedtls_mpi),
	// sizeof(mbedtls_net_context),
	// sizeof(mbedtls_nist_kw_context),
	// sizeof(mbedtls_oid_descriptor_t),
	sizeof(mbedtls_pem_context),
	sizeof(mbedtls_pk_context),
	// sizeof(mbedtls_pk_debug_item),
	// sizeof(mbedtls_pk_rsassa_pss_options),
	// sizeof(mbedtls_pkcs7),
	// sizeof(mbedtls_pkcs7_signed_data),
	// sizeof(mbedtls_pkcs7_signer_info),
	// sizeof(mbedtls_platform_context),
	// sizeof(mbedtls_poly1305_context),
	// sizeof(mbedtls_psa_aead_operation_t),
	// sizeof(mbedtls_psa_cipher_operation_t),
	// sizeof(mbedtls_psa_hash_operation_t),
	// sizeof(mbedtls_psa_hmac_operation_t),
	// sizeof(mbedtls_psa_mac_operation_t),
	// sizeof(mbedtls_psa_pake_operation_t),
	// sizeof(mbedtls_psa_sign_hash_interruptible_operation_)	sizeof(mbedtls_psa_stats_s),
	// sizeof(mbedtls_psa_verify_hash_interruptible_operatio)	sizeof(mbedtls_ripemd160_context),
	// sizeof(mbedtls_rsa_context),
	// sizeof(mbedtls_sha1_context),
	// sizeof(mbedtls_sha256_context),
	// sizeof(mbedtls_sha3_context),
	// sizeof(mbedtls_sha512_context),
	sizeof(mbedtls_ssl_cache_context),
	// sizeof(mbedtls_ssl_cache_entry),
	// sizeof(mbedtls_ssl_ciphersuite_t),
	sizeof(mbedtls_ssl_config),
	sizeof(mbedtls_ssl_context),
	sizeof(mbedtls_ssl_cookie_ctx),
	sizeof(mbedtls_ssl_session),
	sizeof(mbedtls_ssl_ticket_context),
	sizeof(mbedtls_ssl_ticket_key),
	// sizeof(mbedtls_ssl_tls13_application_secrets),
	sizeof(mbedtls_timing_delay_context),
	// sizeof(mbedtls_timing_hr_time),
	sizeof(mbedtls_x509_authority),
	// sizeof(mbedtls_x509_crl),
	// sizeof(mbedtls_x509_crl_entry),
	sizeof(mbedtls_x509_crt),
	// sizeof(mbedtls_x509_crt_profile),
	// sizeof(mbedtls_x509_crt_verify_chain),
	// sizeof(mbedtls_x509_crt_verify_chain_item),
	// sizeof(mbedtls_x509_csr),
	// sizeof(mbedtls_x509_san_list),
	// sizeof(mbedtls_x509_san_other_name),
	// sizeof(mbedtls_x509_subject_alternative_name),
	// sizeof(mbedtls_x509_time),
	sizeof(mbedtls_x509write_cert),
	// sizeof(mbedtls_x509write_csr),
	// sizeof(psa_aead_operation_s),
	// sizeof(psa_cipher_operation_s),
	// sizeof(psa_core_key_attributes_t),
	// sizeof(psa_crypto_driver_pake_inputs_s),
	// sizeof(psa_drv_se_aead_t),
	// sizeof(psa_drv_se_asymmetric_t),
	// sizeof(psa_drv_se_cipher_t),
	// sizeof(psa_drv_se_context_t),
	// sizeof(psa_drv_se_key_derivation_t),
	// sizeof(psa_drv_se_key_management_t),
	// sizeof(psa_drv_se_mac_t),
	// sizeof(psa_drv_se_t),
	// sizeof(psa_hash_operation_s),
	// sizeof(psa_hkdf_key_derivation_t),
	// sizeof(psa_jpake_computation_stage_s),
	// sizeof(psa_key_attributes_s),
	// sizeof(psa_key_derivation_s),
	// sizeof(psa_key_policy_s),
	// sizeof(psa_mac_operation_s),
	// sizeof(psa_pake_cipher_suite_s),
	// sizeof(psa_pake_operation_s),
	// sizeof(psa_sign_hash_interruptible_operation_s),
	// sizeof(psa_tls12_ecjpake_to_pms_t),
	// sizeof(psa_tls12_prf_key_derivation_s),
	// sizeof(psa_verify_hash_interruptible_operation_s),
};

__attribute__((export_name("sizeof"))) int js_size_of(int index) {
	return sizes[index];
}

// Randomization:
__attribute__((import_module("mbedtls"), import_name("random"))) void js_random(void* buff, size_t len);
int f_rng(void* _, unsigned char * buff, size_t bufflen) {
	js_random(buff, bufflen);
	return bufflen;
}
__attribute__((export_name("f_rng"))) int (* f_rng_ptr())(void *, unsigned char *, size_t) {
	return &f_rng;
}

int main() {
	// mbedtls_platform_set_time(get_time);
	return 0;
}
