use std::mem::MaybeUninit;

pub fn md5(chunks: &[&[u8]]) -> [u8; 16] {
	let mut ctx = MaybeUninit::uninit();
	unsafe { mbedtls::mbedtls_md5_init(ctx.as_mut_ptr()); }
	let mut ctx = unsafe { ctx.assume_init() };
	if unsafe { mbedtls::mbedtls_md5_starts(&mut ctx) } != 0 { panic!(); }
	for chunk in chunks {
		if unsafe { mbedtls::mbedtls_md5_update(&mut ctx, chunk.as_ptr(), chunk.len()) } != 0 { panic!(); }
	}
	let mut ret = [0u8; 16];
	if unsafe { mbedtls::mbedtls_md5_finish(&mut ctx, ret.as_mut_ptr()) } != 0 { panic!(); }
	unsafe { mbedtls::mbedtls_md5_free(&mut ctx); }
	ret
}

pub fn sha1_hmac(key_data: &[u8], chunks: &[&[u8]]) -> [u8; 20] {
	let mut ctx = MaybeUninit::uninit();
	unsafe { mbedtls::mbedtls_md_init(ctx.as_mut_ptr()); }
	let mut ctx = unsafe { ctx.assume_init() };
	let md_info = unsafe { mbedtls::mbedtls_md_info_from_type(mbedtls::mbedtls_md_type_t_MBEDTLS_MD_SHA1) };
	if unsafe { mbedtls::mbedtls_md_setup(&mut ctx, md_info, 1) } != 0 { panic!(); }
	if unsafe { mbedtls::mbedtls_md_hmac_starts(&mut ctx, key_data.as_ptr(), key_data.len()) } != 0 { panic!(); }

	for chunk in chunks {
		if unsafe { mbedtls::mbedtls_md_hmac_update(&mut ctx, chunk.as_ptr(), chunk.len()) } != 0 { panic!(); }
	}
	
	let mut ret = [0u8; 20];
	if unsafe { mbedtls::mbedtls_md_hmac_finish(&mut ctx, ret.as_mut_ptr()) } != 0 { panic!(); }
	unsafe { mbedtls::mbedtls_md_free(&mut ctx); }

	ret
}
