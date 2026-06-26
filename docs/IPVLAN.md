# IPVLAN 컨테이너 XDP/TC 방화벽 운영 가이드

## 목차

1. [개요](#1-개요)
2. [아키텍처](#2-아키텍처)
3. [빌드 및 실행](#3-빌드-및-실행)
4. [XDP를 강제 제거하는 방법](#4-xdp를-강제-제거하는-방법)
5. [트러블슈팅](#5-트러블슈팅)

---

## 1. 개요

Auto_XDP의 IPVLAN 방화벽은 Podman IPVLAN 컨테이너 트래픽을 XDP (ingress) + TC (egress) 하이브리드 방식으로 보호합니다.

- **XDP** (`xdp_port_whitelist`): host `eth1` ingress에서 포트 화이트리스트 + conntrack 검사
- **TC** (`tc_egress_track`): 컨테이너 netns `eth0` egress에서 역방향 tuple을 conntrack 맵에 기록

컨테이너가 외부로 연결을 시작하면 TC가 CT 항목을 등록하고, 이후 XDP가 그 항목을 보고 응답 패킷을 통과시킵니다.

---

## 2. 아키텍처

```
 VM.4 (192.168.100.4)
      │  SYN-ACK
      ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  eth1 (192.168.100.3)  — XDP ingress                        │
 │                                                              │
 │  1. Local subnet check (192.168.100.0/24): skip bogon filter │
 │  2. protected_ipv4: CT-only check (container IPs)            │
 │  3. Otherwise: port whitelist + conntrack                    │
 └──────────────────────────────────────────────────────────────┘
      │  XDP_PASS (CT entry found)
      ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  container netns eth0 (192.168.100.10)                       │
 │                                                              │
 │  TC egress (container): SYN → tcp_ct4 (reverse tuple)       │
 └──────────────────────────────────────────────────────────────┘
      │  SYN (egress)
      ▼
 VM.4 (192.168.100.4)

 ┌──────────────────────────────────────────────────────────────┐
 │  eth1 egress  — TC host tracker                              │
 │                                                              │
 │  TC egress (host): host-initiated SYNs → tcp_ct4            │
 │  Allows management traffic (curl/ssh to VMs) to get replies  │
 └──────────────────────────────────────────────────────────────┘
```

**맵 공유**: TC collection은 XDP collection의 `tcp_ct4`, `tcp_ct6`, `udp_ct4`, `udp_ct6` 맵을 `MapReplacements`로 주입받아 같은 커널 맵 객체를 공유합니다.

**bogon 우회**: `xdp_runtime_cfg.local_subnet4_{addr,mask}` 필드에 parent interface 서브넷을 저장합니다. 해당 서브넷 출발지 IP는 bogon 필터를 건너뜁니다 (같은 사설망의 VM 응답이 차단되지 않도록).

---

## 3. 빌드 및 실행

```bash
# Auto_XDP 루트에서
make all

# 로더 실행 예시
sudo ./ipvlan_loader \
    -iface eth1 \
    -pid <container_pid> \
    -xdp-obj xdp_firewall.bpf.o \
    -tc-obj tc_flow_track.bpf.o \
    -container-ip 192.168.100.10 \
    -pin-map

# 테스트
sudo -E bash tests/ipvlan/run_tests.sh
```

---

## 4. XDP를 강제 제거하는 방법

### 배경: BPF link API vs 레거시 xdp

`ipvlan_loader`는 **BPF link API** (`link.AttachXDP`)로 XDP를 부착합니다.  
로더 프로세스가 비정상 종료하거나 디버깅 중 Ctrl-C 없이 kill되면 BPF link fd가 커널에 남아 XDP가 계속 동작합니다.

이 상태에서 레거시 명령어를 사용하면 다음과 같은 오류가 발생합니다:

```
$ sudo ip link set dev eth1 xdpgeneric off
Error: Can't replace active BPF XDP link
```

BPF link로 부착된 XDP는 **fd를 닫아야만** 제거됩니다.

---

### 방법 1: 로더 프로세스 강제 종료 (권장)

로더 프로세스가 살아 있다면 종료하면 BPF link fd도 자동으로 닫힙니다:

```bash
# 로더 PID 확인
pgrep -a ipvlan_loader

# 정상 종료 시도 (SIGTERM)
sudo pkill -TERM -f ipvlan_loader

# 응답 없으면 강제 종료 (SIGKILL)
sudo pkill -KILL -f ipvlan_loader

# sudo 래퍼가 남아 있을 경우
sudo kill -9 $(pgrep -f "sudo.*ipvlan_loader")
```

> **주의**: `pkill -f`는 `sudo` 래퍼 프로세스를 대상으로 할 수 있습니다. 실제 `ipvlan_loader` 바이너리 프로세스에 직접 SIGKILL을 보내야 BPF link가 닫힙니다. `pgrep -a ipvlan_loader`로 두 PID를 모두 확인한 후 바이너리 PID에 `kill -9`를 보내세요.

제거 확인:

```bash
ip link show eth1 | grep -i xdp
# xdp 항목이 없으면 제거 완료
```

---

### 방법 2: xdp_detach 유틸리티 사용

로더가 이미 종료되었으나 BPF link가 남아 있는 경우(예: 커널 버그, 다른 프로세스가 fd를 상속받은 경우), `xdp_detach` 유틸리티로 직접 제거합니다:

```bash
# 빌드 (make all 시 자동 포함)
make go

# 특정 인터페이스의 XDP BPF link 제거
sudo ./xdp_detach eth1

# 출력 예시
# [info] eth1 (ifindex=3) 의 XDP BPF link 탐색...
# [info] XDP link 발견: ID=42, ifindex=3 → 제거 중...
# [ok] XDP link 제거 완료
```

**동작 원리**: `xdp_detach`는 `link.Iterator` (cilium/ebpf v0.16.0 이상)로 커널의 모든 BPF link를 순회하여 `XDPType`이고 대상 `ifindex`와 일치하는 link의 fd를 닫습니다. fd를 닫으면 커널이 해당 인터페이스에서 XDP 프로그램을 자동으로 제거합니다.

---

### 방법 3: BPF 파일시스템 pinned 맵 정리

XDP/TC를 제거한 후 pinned 맵도 함께 정리합니다:

```bash
sudo rm -rf /sys/fs/bpf/auto_xdp
```

---

### 방법 4: 상태 확인

```bash
# XDP 부착 여부 확인
ip link show eth1 | grep xdp

# 커널 BPF link 목록 (root 권한 필요)
sudo bpftool link show type xdp 2>/dev/null || \
    ls /proc/*/fdinfo/* 2>/dev/null | xargs grep -l "link_type.*xdp" 2>/dev/null

# pinned 맵 확인
ls /sys/fs/bpf/auto_xdp/ 2>/dev/null

# TC filter 확인 (컨테이너 netns 안에서)
sudo nsenter -t <container_pid> -n -- tc filter show dev eth0 egress
```

---

### 종합 정리 스크립트

```bash
#!/usr/bin/env bash
# XDP + TC + pinned 맵 전체 정리
sudo pkill -KILL -f ipvlan_loader 2>/dev/null || true
sudo ./xdp_detach eth1 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/auto_xdp 2>/dev/null || true
echo "정리 완료. 확인:"
ip link show eth1 | grep -i xdp && echo "XDP 남아있음!" || echo "XDP 제거됨"
```

---

## 5. 트러블슈팅

### 시나리오 1 (egress stateful) 실패: success=0, timeout=N

**원인 1: bogon 필터가 RFC1918 응답 차단**

XDP의 bogon 필터가 192.168.0.0/16 (RFC1918) 출발지 IP를 차단합니다. 같은 서브넷의 VM (예: 192.168.100.4)과 통신하는 IPVLAN 컨테이너는 bogon 우회가 필요합니다.

로더에 `-container-ip` 플래그로 컨테이너 IP를 등록하면 `protected_ipv4` 맵에 추가되어 해당 IP를 목적지로 하는 패킷에는 bogon 필터가 적용되지 않습니다.

```bash
# 올바른 로더 실행 (container-ip 반드시 지정)
sudo ./ipvlan_loader -iface eth1 -pid <PID> \
    -xdp-obj xdp_firewall.bpf.o \
    -tc-obj tc_flow_track.bpf.o \
    -container-ip 192.168.100.10 -pin-map
```

**원인 2: TC/XDP 맵 크기 불일치**

`tc_flow_track.c`의 `tcp_ct6`, `udp_ct6` max_entries가 `maps.h`의 `CT_MAP_MAX_ENTRIES_V6` (196608)와 달라 `MapReplacements`가 실패합니다. 두 파일의 max_entries를 일치시킨 후 `make bpf`로 재빌드하세요.

**원인 3: CT key 방향 불일치**

TC는 컨테이너가 보내는 패킷(SYN)을 보고 **역방향** tuple을 저장합니다:
`fill_flow_key_v4(ip->daddr, ip->saddr, tcp->dest, tcp->source)` — 서버→컨테이너 방향으로 저장.

XDP는 서버에서 오는 SYN-ACK를 보고 같은 tuple로 조회합니다. 방향이 맞지 않으면 CT 항목을 찾지 못해 XDP_DROP됩니다.

### xdp_detach: XDP link 없음 출력됨

프로세스가 이미 종료되어 BPF link가 자동 제거된 것입니다. `ip link show eth1 | grep xdp`로 확인하세요. 이미 제거된 경우 정상입니다.

### TC filter가 제거되지 않음

컨테이너 삭제 시 netns가 사라지면서 TC filter도 자동 제거됩니다. 만약 남아있다면:

```bash
sudo nsenter -t <container_pid> -n -- tc filter del dev eth0 egress
```
