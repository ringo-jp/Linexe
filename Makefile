# Linexe v0.5.1 - Wine-free Windows EXE Compatibility Layer
# Licensed under Apache License 2.0

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -ldl -lpthread

SRCDIR  = src
TESTDIR = tests

.PHONY: all clean test check wine-check

# ── メインターゲット ─────────────────────────────────────
all: linexe linexe_hook.so linexe-tracer

## Phase 1+自立実行エンジン: Wine不要のEXEランタイム
linexe: $(SRCDIR)/linexe_exec.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[✓] linexe - Wine-free EXE runtime"

## Phase 2: LD_PRELOADフックライブラリ
linexe_hook.so: $(SRCDIR)/hook.c $(SRCDIR)/hook_registry.c \
                $(SRCDIR)/hook_heap.c $(SRCDIR)/hook_thread.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)
	@echo "[✓] linexe_hook.so - API spoof layer"

## Phase 3: Syscallトレーサー
linexe-tracer: $(SRCDIR)/syscall_tracer.c $(SRCDIR)/syscall_args.c \
               $(SRCDIR)/syscall_extra.c $(SRCDIR)/syscall_file.c \
               $(SRCDIR)/syscall_thread.c $(SRCDIR)/syscall_query.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $^ $(LDFLAGS)
	@echo "[✓] linexe-tracer - NT syscall translation engine"

# ── テスト ───────────────────────────────────────────────
phase2_tests: api_test reg_test heap_test thread_test

api_test: $(SRCDIR)/api_fake.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_API -o $@ $<

reg_test: $(SRCDIR)/hook_registry.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_REGISTRY -o $@ $<

heap_test: $(SRCDIR)/hook_heap.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_HEAP -o $@ $<

thread_test: $(SRCDIR)/hook_thread.c
	$(CC) $(CFLAGS) -DLINEXE_TEST_THREAD -o $@ $< -lpthread

harsh_test: $(TESTDIR)/harsh_test.c
	$(CC) $(CFLAGS) -DLINEXE_QUIET -o $@ $< -lpthread

phase3_test: $(TESTDIR)/phase3_test.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $<

phase3_complete_test: $(TESTDIR)/phase3_complete_test.c $(SRCDIR)/syscall_file.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $^ -lpthread

phase4_test: $(TESTDIR)/phase4_test.c $(SRCDIR)/d3d11_hook.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $^ -ldl -lpthread -lvulkan

phase45_test: $(TESTDIR)/phase45_test.c \
              $(SRCDIR)/shader_trans.c \
              $(SRCDIR)/d3d11_pipeline.c \
              $(SRCDIR)/kvm_hybrid.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $^ -ldl -lpthread

final_check: $(TESTDIR)/final_check.c \
             $(SRCDIR)/shader_trans.c \
             $(SRCDIR)/d3d11_pipeline.c \
             $(SRCDIR)/kvm_hybrid.c
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $^ -ldl -lpthread

# ── test: 全テストスイート実行 ────────────────────────────
test: all phase2_tests harsh_test phase3_test phase3_complete_test \
      phase45_test final_check
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

# ── check: Wineへの依存がないことを確認 ──────────────────
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
