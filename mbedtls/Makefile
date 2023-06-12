CC = wasi-sdk-20.0/bin/clang
CFLAGS = -Os -DMBEDTLS_CONFIG_FILE=\"config.h\" -Iinclude -Ivendor/include

.PHONY = all clean

all: mbedtls.wasm

obj:
	mkdir -p obj/c_src obj/vendor/library

obj/c_src/%.o: c_src/%.c | obj include/*.h
	$(CC) $(CFLAGS) -c -o $@ $^

obj/vendor/%.o: vendor/%.c | obj include/*.h
	$(CC) $(CFLAGS) -c -fvisibility=default -o $@ $^
	
mbedtls.wasm: $(patsubst %.c,obj/%.o,$(wildcard c_src/*.c) $(wildcard vendor/library/*.c))
	$(CC) $(CFLAGS) -Wl,--export-dynamic,--export=malloc,--export=free,--export=realloc,--export=strlen -o dist/$@ $^
	wasm2wat dist/$@ | grep -E "\(import|\(export"

clean:
	rm -rf obj
	rm dist/*.wasm dist/*.wat
