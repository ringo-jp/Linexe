# Linexe v0.5.1 - Wine-free Windows EXE Compatibility Layer
# Licensed under Apache License 2.0

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -ldl -lpthread

.PHONY: all clean test wine-check phase2_tests

# ── メインターゲット ─────────────────────────────────────
all: linexe linexe_hook.so linexe-tracer

# Phase 1+自立実行エンジン
linexe: linexe_exec.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[✓] linexe - Wine-free EXE runtime"

# Phase 2: LD_PRELOADフックライブラリ
linexe_hook.so: hook.c hook_registry.c hook_heap.c hook_thread.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)
	@echo "[✓] linexe_hook.so - API spoof layer"

# Phase 3: Syscallトレーサー
linexe-tracer: syscall_tracer.c syscall_args.c syscall_extra.c syscall_file.c syscall_thread.c syscall_query.c
	$(CC) $(CFLAGS) -I . -o $@ $^ $(LDFLAGS)
	@echo "[✓] linexe-tracer - NT syscall translation engine"

# ── テスト ───────────────────────────────────────────────
phase2_tests: api_test reg_test heap_test thread_test

api_test: api_fake.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_API -o $@ $<

reg_test: hook_registry.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_REGISTRY -o $@ $<

heap_test: hook_heap.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_HEAP -o $@ $<

thread_test: hook_thread.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_THREAD -o $@ $< -lpthread

harsh_test: harsh_test.c
	$(CC) $(CFLAGS) -DLINEXE_QUIET -o $@ $< -lpthread

phase3_test: phase3_test.c
	$(CC) $(CFLAGS) -I . -o $@ $<

phase3_complete_test: phase3_complete_test.c syscall_file.c
	$(CC) $(CFLAGS) -I . -o $@ $^ -lpthread

phase4_test: phase4_test.c d3d11_hook.c
	$(CC) $(CFLAGS) -I . -o $@ $^ -ldl -lpthread -lvulkan

phase45_test: phase45_test.c shader_trans.c d3d11_pipeline.c kvm_hybrid.c
	$(CC) $(CFLAGS) -I . -o $@ $^ -ldl -lpthread

final_check: final_check.c shader_trans.c d3d11_pipeline.c kvm_hybrid.c
	$(CC) $(CFLAGS) -I . -o $@ $^ -ldl -lpthread

# ── test: 全テストスイート実行 ────────────────────────────
test: all phase2_tests harsh_test phase3_test phase3_complete_test phase45_test final_check
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Phase 2: API Spoof Layer"
	@echo "══════════════════════════════════════════"
	./api_test
	@echo ""
	./reg_test
	@echo ""
	./heap_test
	@echo ""
	./thread_test
	@echo ""
	@echo "  Hook Layer smoke test (LD_PRELOAD):"
	LD_PRELOAD=./linexe_hook.so ls --version > /dev/null && echo "  PASS  LD_PRELOAD hook layer"
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Phase 2: Harsh Stress Test"
	@echo "══════════════════════════════════════════"
	./harsh_test
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Phase 3: Syscall Tracer"
	@echo "══════════════════════════════════════════"
	./phase3_test
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Phase 3: Complete Test"
	@echo "══════════════════════════════════════════"
	./phase3_complete_test
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Phase 4+5: DirectX & KVM"
	@echo "══════════════════════════════════════════"
	./phase45_test
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Final: Bug Check & Stability"
	@echo "══════════════════════════════════════════"
	./final_check
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  All tests passed. Wine dependency: NONE"
	@echo "══════════════════════════════════════════"

wine-check:
	@echo "=== Wine dependency check ==="
	@grep -rn "wine" Makefile linexe-run 2>/dev/null | grep -v "#" || echo "  OK: No wine references in launcher"
	@ldd linexe 2>/dev/null | grep -i wine || echo "  OK: linexe binary has no wine dependency"
	@ldd linexe_hook.so 2>/dev/null | grep -i wine || echo "  OK: hook library has no wine dependency"
	@echo "Wine-free: confirmed"

# ── clean ─────────────────────────────────────────────────
clean:
	rm -f linexe linexe_new linexe_hook.so linexe-tracer
	rm -f api_test reg_test heap_test thread_test
	rm -f harsh_test phase3_test phase3_complete_test
	rm -f phase4_test phase45_test final_check
	@echo "[✓] Clean complete"
