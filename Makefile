## Linexe Makefile

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -ldl

.PHONY: all clean test

all: linexe linexe_hook.so api_test

## Phase 1: PE インスペクタ
linexe: src/pe_loader.c
	$(CC) $(CFLAGS) -o $@ $<

## Phase 2: フックライブラリ（共有ライブラリ）
linexe_hook.so: src/hook.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)

## Phase 2: API偽装セルフテスト
api_test: src/api_fake.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_API -o $@ $<

## テスト実行
test: all
	@echo "=== Phase 1: PE Loader ==="
	@echo "(EXEファイルが必要: make test EXE=yourfile.exe)"
ifdef EXE
	./linexe $(EXE)
endif
	@echo ""
	@echo "=== Phase 2: API Fake Self Test ==="
	./api_test
	@echo ""
	@echo "=== Phase 2: Hook Layer (LD_PRELOAD test) ==="
	@echo "Activate hook..."
	LD_PRELOAD=./linexe_hook.so ls --version > /dev/null
	@echo "Hook layer active OK"

clean:
	rm -f linexe linexe_hook.so api_test
