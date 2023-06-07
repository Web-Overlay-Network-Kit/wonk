CC = wasi-sdk-20.0/bin/clang
CFLAGS_COMMON = -DMBEDTLS_CONFIG_FILE=\"config.h\" -fvisibility=default -Iinclude -Ivendor/include -Wl,--import-undefined,--export-dynamic,--export=malloc,--export=free,--export=realloc,--export=strlen
ifdef RELEASE
CFLAGS = -Os $(CFLAGS_COMMON)
else
CFLAGS = -Os -g $(CFLAGS_COMMON)
endif

.PHONY = all clean


all: mbedtls.wasm

mbedtls.wasm: c_src/*.c vendor/library/*.c
	$(CC) $(CFLAGS) -o dist/$@ $^
	wasm2wat dist/$@ | grep -E "\(import|\(export"

clean:
	rm dist/*.wasm dist/*.wat
