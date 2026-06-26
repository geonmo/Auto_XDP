# Makefile — Auto_XDP IPVLAN Egress Tracker
#
# 빌드: make all
# 테스트: cd tests/ipvlan && bash run_tests.sh

ARCH       := $(shell uname -m)
AUTO_XDP_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

XDP_SRC    := bpf/xdp_firewall.c
TC_SRC     := tc_flow_track.c
XDP_OBJ    := xdp_firewall.bpf.o
TC_OBJ     := tc_flow_track.bpf.o
GO_BIN     := ipvlan_loader
GO_MAIN    := ./cmd/ipvlan_loader

ifeq ($(ARCH),x86_64)
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_x86 -D__x86_64__
else ifeq ($(ARCH),aarch64)
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_arm64 -D__aarch64__
else
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_$(ARCH)
endif

INCLUDE_PATHS := -I bpf/include -I . -I /usr/include -I /usr/include/bpf
ifneq ($(wildcard /usr/include/$(shell gcc -print-multiarch 2>/dev/null)),)
  INCLUDE_PATHS += -I /usr/include/$(shell gcc -print-multiarch 2>/dev/null)
endif

.PHONY: all bpf go clean check-xdp watch-map

all: bpf go

bpf: $(XDP_OBJ) $(TC_OBJ)

$(XDP_OBJ): $(XDP_SRC) bpf/include/*.h handlers/xdp_slot_ctx.h
	@echo "[bpf] 컴파일: $(XDP_SRC) → $(XDP_OBJ)"
	clang -O3 -g \
	  -target bpf \
	  -mcpu=v3 \
	  $(BPF_ARCH_FLAGS) \
	  $(INCLUDE_PATHS) \
	  -fno-stack-protector \
	  -Wall -Wno-unused-value \
	  -c $(XDP_SRC) -o $(XDP_OBJ)
	@echo "[bpf] 완료: $(XDP_OBJ)"
	@llvm-objdump -h $(XDP_OBJ) 2>/dev/null | grep -E '^\s+[0-9]+ xdp' || true

$(TC_OBJ): $(TC_SRC) bpf/include/ct_flags.h
	@echo "[bpf] 컴파일: $(TC_SRC) → $(TC_OBJ)"
	clang -O2 -g \
	  -target bpf \
	  $(BPF_ARCH_FLAGS) \
	  $(INCLUDE_PATHS) \
	  -fno-stack-protector \
	  -Wall -Wno-unused-value \
	  -c $(TC_SRC) -o $(TC_OBJ)
	@echo "[bpf] 완료: $(TC_OBJ)"
	@llvm-objdump -h $(TC_OBJ) 2>/dev/null | grep -E '^\s+[0-9]+ classifier' || true

go: $(GO_BIN)

$(GO_BIN): $(GO_MAIN)/main.go go.mod
	@echo "[go] 의존성 다운로드..."
	go mod tidy
	@echo "[go] 빌드: $(GO_BIN)"
	go build -o $(GO_BIN) $(GO_MAIN)
	@echo "[go] 완료: $(GO_BIN)"

clean:
	rm -f $(XDP_OBJ) $(TC_OBJ) $(GO_BIN)
	@sudo rm -rf /sys/fs/bpf/auto_xdp 2>/dev/null || true
	@echo "[clean] 완료"

check-xdp:
	@echo "현재 eth1에 attach된 XDP 프로그램:"
	sudo bpftool net show dev eth1 2>/dev/null || ip link show eth1

watch-map:
	@echo "tcp_ct4 실시간 모니터링 (-pin-map 옵션으로 실행 중이어야 함)"
	watch -n 1 'sudo bpftool map dump pinned /sys/fs/bpf/auto_xdp/tcp_ct4 2>/dev/null | head -40'
