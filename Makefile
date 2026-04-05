CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -ldl -lpthread

.PHONY: all clean test launcher

all: linexe linexe_hook.so api_test reg_test heap_test thread_test launcher

linexe: src/pe_loader.c
	$(CC) $(CFLAGS) -o $@ $<

linexe_hook.so: src/hook.c src/hook_registry.c src/hook_heap.c src/hook_thread.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)

api_test: src/api_fake.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_API -o $@ $<

reg_test: src/hook_registry.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_REGISTRY -o $@ $<

heap_test: src/hook_heap.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_HEAP -o $@ $<

thread_test: src/hook_thread.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_THREAD -o $@ $< -lpthread

launcher:
	@printf '#!/bin/bash\nSCRIPT_DIR="$$(dirname "$$(realpath "$$0")")"\nHOOK="$$SCRIPT_DIR/linexe_hook.so"\n[ -f "$$HOOK" ] || { echo "Error: linexe_hook.so not found."; exit 1; }\n[ -n "$$1" ] || { echo "Usage: linexe-run <file.exe> [args...]"; exit 1; }\necho "[Linexe] Hook layer active."\nLD_PRELOAD="$$HOOK" wine "$$@"\n' > linexe-run
	@chmod +x linexe-run
	@echo "[*] linexe-run created."

test: all
	@echo ""
	@echo "=== Phase 2: API Fake ==="
	./api_test
	@echo ""
	@echo "=== Phase 2: Virtual Registry ==="
	./reg_test
	@echo ""
	@echo "=== Phase 2: Heap Hook ==="
	./heap_test
	@echo ""
	@echo "=== Phase 2: Thread Hook ==="
	./thread_test
	@echo ""
	@echo "=== Hook Layer (LD_PRELOAD smoke test) ==="
	LD_PRELOAD=./linexe_hook.so ls --version > /dev/null && echo "Hook layer OK"
	@echo ""
	@echo "All Phase 2 tests passed."

clean:
	rm -f linexe linexe_hook.so linexe-run
	rm -f api_test reg_test heap_test thread_test
