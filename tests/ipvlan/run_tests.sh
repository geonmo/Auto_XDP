#!/usr/bin/env bash
# ============================================================================
# run_tests.sh — Auto_XDP IPVLAN stateful firewall test suite
#
# 테스트 구성:
#   host  (192.168.100.3) : IPVLAN 컨테이너 + XDP (eth1) + TC (컨테이너 슬레이브)
#   VM.4  (192.168.100.4) : target_server — 컨테이너가 접속하는 합법적 서버
#   VM.5  (192.168.100.5) : attacker     — 컨테이너에 미등록 인바운드 전송
#
# 시나리오:
#   1. Container → VM.4 stateful egress (TC 등록 → XDP 회신 통과 확인)
#   2. VM.5 → container unsolicited (XDP_DROP 확인)
#   2-b. VM.5 → container CT port spoof (CT 5-tuple 특이성 검증, L2 only)
#   2-c. VM.5 → container IP spoof saddr=VM.4 (IP 스푸핑 차단 검증, L2 only)
#   3. IPVLAN 모드 비교: L2 / L3 / L3s 각각에서 시나리오 1+2 반복
#
# 사전 조건:
#   make all  (Auto_XDP 루트에서)
#   VM.4, VM.5에 SSH 접속 가능 (ansible이 자동 배포)
#
# 옵션:
#   --skip-ansible  : Ansible 배포 생략 (원격 서비스가 이미 실행 중인 경우)
# ============================================================================

set -euo pipefail

# ── 경로 설정 ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOADER_BIN="$PROJECT_DIR/ipvlan_loader"
XDP_BPF_OBJ="$PROJECT_DIR/xdp_firewall.bpf.o"
TC_BPF_OBJ="$PROJECT_DIR/tc_flow_track.bpf.o"
CONTAINER_IMAGE="localhost/ct-app:latest"

# ── 네트워크 설정 ────────────────────────────────────────────────────────────
HOST_IFACE="eth1"
CONTAINER_IFACE="eth0"
CONTAINER_IP="192.168.100.10"
TARGET_IP="192.168.100.4"
ATTACKER_IP="192.168.100.5"
TARGET_PORT=8080
CONTAINER_PORT=8080
CONTAINER_API=7070

# ── 옵션 파싱 ────────────────────────────────────────────────────────────────
SKIP_ANSIBLE=false
for arg in "$@"; do
    [[ "$arg" == "--skip-ansible" ]] && SKIP_ANSIBLE=true
done

# ── 컬러 출력 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
step()  { echo -e "${CYAN}${BOLD}>>> $*${NC}"; }
banner(){ echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"; echo -e "${BOLD}  $*${NC}"; echo -e "${BOLD}═══════════════════════════════════════════════${NC}"; }

# ── 글로벌 상태 ──────────────────────────────────────────────────────────────
LOADER_PID=""
CONTAINER_NAME=""
RESULTS_JSON="$SCRIPT_DIR/test_results_$(date +%Y%m%d_%H%M%S).json"
declare -A SCENARIO1_RESULT SCENARIO2_RESULT SCENARIO2_CTSPOOF_RESULT SCENARIO2_IPSPOOF_RESULT

# ── 정리 핸들러 ──────────────────────────────────────────────────────────────
cleanup() {
    info "정리 중..."
    _stop_loader
    _stop_container
    # IPVLAN 네트워크 제거
    for m in l2 l3 l3s; do
        sudo podman network rm "ct-net-$m" 2>/dev/null || true
    done
    sudo rm -rf /sys/fs/bpf/auto_xdp 2>/dev/null || true
}
trap cleanup EXIT

# ── 헬퍼 함수 ────────────────────────────────────────────────────────────────

_json_field() {
    # Usage: _json_field <json_string> <field>
    echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2', 0))" 2>/dev/null || echo 0
}

# 외부 HTTP 헬스체크 (VM.4, VM.5 등 별도 호스트용)
_wait_http() {
    local url=$1 max=${2:-15} i
    for i in $(seq 1 $max); do
        curl -fsS --max-time 2 "$url" &>/dev/null && return 0
        sleep 1
    done
    return 1
}

# IPVLAN 제약: 호스트에서 컨테이너 IP 직접 접근 불가 → podman exec 경유
# 컨테이너 REST API 준비 대기
_wait_container_api() {
    local max=${1:-20} i
    for i in $(seq 1 $max); do
        sudo podman exec "$CONTAINER_NAME" \
            curl -fsS --max-time 2 "http://localhost:$CONTAINER_API/api/health" &>/dev/null \
            && return 0
        sleep 1
    done
    return 1
}

# 컨테이너 내부 API 호출 (podman exec 경유)
_capi() {
    # Usage: _capi /api/path [curl-extra-args...]
    local path=$1; shift
    sudo podman exec "$CONTAINER_NAME" \
        curl -fsS --max-time 3 "$@" "http://localhost:$CONTAINER_API$path" 2>/dev/null || echo '{}'
}

_build_image() {
    step "컨테이너 이미지 빌드: $CONTAINER_IMAGE"
    sudo podman build -t ct-app:latest "$SCRIPT_DIR/container-app/"
    pass "이미지 빌드 완료"
}

_start_container() {
    local mode=$1
    local net="ct-net-$mode"
    CONTAINER_NAME="ct-test-$mode"

    # 기존 동일 컨테이너 제거
    sudo podman rm -f "$CONTAINER_NAME" 2>/dev/null || true

    # IPVLAN 네트워크 생성 (기존 있으면 재사용)
    if ! sudo podman network inspect "$net" &>/dev/null; then
        info "IPVLAN $mode 네트워크 생성: $net"
        sudo podman network create \
            --driver ipvlan \
            --opt "parent=$HOST_IFACE" \
            --opt "mode=$mode" \
            --subnet 192.168.100.0/24 \
            --gateway 192.168.100.1 \
            --disable-dns \
            "$net"
    fi

    info "컨테이너 시작 (mode=$mode, ip=$CONTAINER_IP)..."
    sudo podman run -d \
        --name "$CONTAINER_NAME" \
        --network "$net:ip=$CONTAINER_IP" \
        --cap-add CAP_NET_RAW \
        --cap-add CAP_NET_ADMIN \
        -e TARGET_IP="$TARGET_IP" \
        -e TARGET_PORT="$TARGET_PORT" \
        -e ATTACKER_IP="$ATTACKER_IP" \
        -e LISTEN_PORT="$CONTAINER_PORT" \
        -e API_PORT="$CONTAINER_API" \
        -e CLIENT_INTERVAL=2 \
        -e NODE_NAME="container-$mode" \
        "$CONTAINER_IMAGE"

    sleep 1
    local pid
    pid=$(sudo podman inspect --format '{{.State.Pid}}' "$CONTAINER_NAME")
    info "컨테이너 PID: $pid"
}

_start_loader() {
    local mode=$1
    local pid
    pid=$(sudo podman inspect --format '{{.State.Pid}}' "$CONTAINER_NAME")

    info "eBPF 로더 시작 (mode=$mode, pid=$pid, iface=$HOST_IFACE)..."
    sudo "$LOADER_BIN" \
        -iface "$HOST_IFACE" \
        -pid "$pid" \
        -container-iface "$CONTAINER_IFACE" \
        -xdp-obj "$XDP_BPF_OBJ" \
        -tc-obj "$TC_BPF_OBJ" \
        -container-ip "$CONTAINER_IP" \
        -pin-map \
        > "/tmp/ct-loader-$mode.log" 2>&1 &
    LOADER_PID=$!

    sleep 2

    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        fail "로더 시작 실패. 로그:"
        tail -20 "/tmp/ct-loader-$mode.log" >&2
        return 1
    fi
    pass "eBPF 로더 실행 중 (PID=$LOADER_PID)"
}

_stop_loader() {
    if [[ -n "$LOADER_PID" ]]; then
        # LOADER_PID는 sudo 래퍼 PID — 실제 로더 바이너리에 직접 SIGTERM 전달
        sudo pkill -TERM -f "$(basename "$LOADER_BIN")" 2>/dev/null || true
        sleep 1
        sudo pkill -KILL -f "$(basename "$LOADER_BIN")" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
        LOADER_PID=""
    fi
    sudo rm -rf /sys/fs/bpf/auto_xdp 2>/dev/null || true
}

_stop_container() {
    if [[ -n "$CONTAINER_NAME" ]]; then
        sudo podman stop "$CONTAINER_NAME" 2>/dev/null || true
        sudo podman rm "$CONTAINER_NAME" 2>/dev/null || true
        CONTAINER_NAME=""
    fi
}

# CT 맵 엔트리 수 조회 (bpftool 있으면 사용, 없으면 핀 파일 존재 여부만 확인)
_get_ct_entries() {
    local pin_path="/sys/fs/bpf/auto_xdp/tcp_ct4"
    if command -v bpftool &>/dev/null; then
        sudo bpftool map dump pinned "$pin_path" 2>/dev/null | grep -c 'key' || echo 0
    elif [[ -e "$pin_path" ]]; then
        echo "pinned(count_unavail)"
    else
        echo 0
    fi
}

_dump_ct_map() {
    info "tcp_ct4 맵 (핀: /sys/fs/bpf/auto_xdp/tcp_ct4):"
    if command -v bpftool &>/dev/null; then
        sudo bpftool map dump pinned /sys/fs/bpf/auto_xdp/tcp_ct4 2>/dev/null \
            | head -30 || echo "  (맵 덤프 불가)"
    elif [[ -e /sys/fs/bpf/auto_xdp/tcp_ct4 ]]; then
        echo "  (bpftool 미설치 — 핀 파일 존재 확인됨)"
    else
        echo "  (맵 핀 없음)"
    fi
}

# ── 컨테이너 → VM.4 연결에 사용된 ephemeral 포트 조회 ────────────────────────
# 1차: container REST API /api/client-ports (container_app.py가 직접 추적)
# 2차: /proc/net/tcp fallback (TIME_WAIT 포함)
_get_container_ct_ports() {
    # 1차: REST API (가장 신뢰도 높음 — TIME_WAIT 만료 후에도 유효)
    local api_json
    api_json=$(_capi /api/client-ports 2>/dev/null)
    if [[ -n "$api_json" && "$api_json" != "{}" ]]; then
        local ports
        ports=$(echo "$api_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('ports', []):
    print(p)
" 2>/dev/null)
        if [[ -n "$ports" ]]; then
            echo "$ports" | head -10
            return
        fi
    fi

    # 2차: /proc/net/tcp 파싱 (fallback)
    sudo podman exec "$CONTAINER_NAME" python3 - <<PYEOF 2>/dev/null | head -10
import socket

def hex_to_ip(h):
    return socket.inet_ntoa(bytes.fromhex(h)[::-1])

def hex_to_port(h):
    return int(h, 16)

target_ip   = '$TARGET_IP'
target_port = $TARGET_PORT
seen = set()
try:
    with open('/proc/net/tcp') as f:
        next(f)
        for line in f:
            parts = line.split()
            if len(parts) < 4:
                continue
            _,  lport_h = parts[1].split(':')
            raddr, rport_h = parts[2].split(':')
            rip   = hex_to_ip(raddr)
            rport = hex_to_port(rport_h)
            if rip == target_ip and rport == target_port:
                lport = hex_to_port(lport_h)
                if lport not in seen:
                    seen.add(lport)
                    print(lport)
except Exception:
    pass
PYEOF
}

# ── 시나리오 1: 컨테이너 → VM.4 (stateful egress) ──────────────────────────
_run_scenario1() {
    local mode=$1
    step "시나리오 1 [mode=$mode]: Container → VM.4 (stateful egress + XDP reply pass)"

    # target 통계 초기화
    curl -fsS -X POST "http://$TARGET_IP:9090/api/reset" &>/dev/null || true
    _capi /api/reset -X POST &>/dev/null || true

    info "클라이언트 요청 누적 대기 (8초)..."
    sleep 8

    # conntrack map 확인 (TC 등록 여부)
    local map_entries
    map_entries=$(_get_ct_entries)
    info "tcp_ct4 엔트리 수: $map_entries"

    # 컨테이너 클라이언트 결과 (podman exec 경유)
    local client_json success timeout_cnt
    client_json=$(_capi /api/summary)
    success=$(  _json_field "$client_json" "success")
    timeout_cnt=$(_json_field "$client_json" "timeout")
    info "컨테이너 클라이언트: success=$success timeout=$timeout_cnt (raw: $client_json)"

    # VM.4 수신 결과
    local target_json target_total
    target_json=$(curl -fsS --max-time 3 "http://$TARGET_IP:9090/api/stats" 2>/dev/null || echo '{}')
    target_total=$(_json_field "$target_json" "total")
    info "VM.4 수신 건수: $target_total (raw: $target_json)"

    if [[ "$success" -gt 0 && "$target_total" -gt 0 ]]; then
        pass "시나리오 1 [$mode] PASS: 컨테이너→VM.4 $success회 성공, VM.4 수신 $target_total회, CT map=$map_entries"
        SCENARIO1_RESULT[$mode]="PASS (success=$success, target=$target_total)"
    elif [[ "$map_entries" != "0" && "$success" -eq 0 ]]; then
        fail "시나리오 1 [$mode] PARTIAL: TC 등록($map_entries) 확인, 회신 수신 실패 (라우팅 설정 필요 가능)"
        SCENARIO1_RESULT[$mode]="PARTIAL (tc_ok, routing_issue)"
    else
        fail "시나리오 1 [$mode] FAIL: success=$success map=$map_entries"
        SCENARIO1_RESULT[$mode]="FAIL (success=$success)"
    fi
}

# ── 시나리오 2: VM.5 → 컨테이너 (unsolicited inbound drop) ──────────────────
_run_scenario2() {
    local mode=$1
    step "시나리오 2 [mode=$mode]: VM.5 → container (XDP_DROP 검증)"

    # attacker 초기화
    curl -fsS -X POST "http://$ATTACKER_IP:8001/api/reset" &>/dev/null || true

    info "VM.5에서 컨테이너($CONTAINER_IP:$CONTAINER_PORT)로 10회 TCP 접속 시도..."
    local attack_resp
    attack_resp=$(curl -fsS -X POST "http://$ATTACKER_IP:8001/api/attack" \
        -H 'Content-Type: application/json' \
        -d "{\"target\":\"$CONTAINER_IP\",\"port\":$CONTAINER_PORT,\"count\":10,\"timeout\":2.0}" \
        2>/dev/null || echo '{"error":"unreachable"}')
    info "공격 시작 응답: $attack_resp"

    # 공격 완료 대기 (10 × 2.0s timeout + 10 × 0.2s sleep + 여유)
    info "공격 완료 대기 (최대 30초)..."
    local waited=0
    while [[ $waited -lt 30 ]]; do
        sleep 3
        waited=$((waited + 3))
        local running
        running=$(curl -fsS --max-time 2 "http://$ATTACKER_IP:8001/api/attack/status" 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('running',True))" 2>/dev/null || echo True)
        [[ "$running" == "False" ]] && break
    done

    # 결과 수집
    local status_json timeout_cnt connected_cnt refused_cnt
    status_json=$(curl -fsS --max-time 3 "http://$ATTACKER_IP:8001/api/attack/status" 2>/dev/null || echo '{}')
    timeout_cnt=$(  _json_field "$status_json" "timeout")
    connected_cnt=$(_json_field "$status_json" "connected")
    refused_cnt=$(  _json_field "$status_json" "refused")
    info "공격 결과: timeout=$timeout_cnt connected=$connected_cnt refused=$refused_cnt (raw: $status_json)"

    # 컨테이너 서버 수신 확인 (0이어야 함, podman exec 경유)
    local server_json from_attacker
    server_json=$(_capi /api/server-stats)
    from_attacker=$(_json_field "$server_json" "from_attacker")
    info "컨테이너 서버 수신 (from VM.5): $from_attacker"

    if [[ "$connected_cnt" -eq 0 && "$refused_cnt" -eq 0 && "$from_attacker" -eq 0 ]]; then
        pass "시나리오 2 [$mode] PASS: 모든 ${timeout_cnt}개 패킷 XDP_DROP 확인"
        SCENARIO2_RESULT[$mode]="PASS (dropped=$timeout_cnt)"
    elif [[ "$connected_cnt" -gt 0 ]]; then
        fail "시나리오 2 [$mode] FAIL: ${connected_cnt}개 연결 성공 (XDP_PASS 발생!)"
        SCENARIO2_RESULT[$mode]="FAIL (connected=$connected_cnt)"
    else
        fail "시나리오 2 [$mode] FAIL: timeout=$timeout_cnt refused=$refused_cnt from_attacker=$from_attacker"
        SCENARIO2_RESULT[$mode]="FAIL (refused=$refused_cnt)"
    fi
}

# ── 시나리오 2-b: VM.5 → container CT port spoof (5-tuple specificity) ───────
# After scenario 1 establishes container→VM.4 connections (CT key: saddr=VM.4),
# VM.5 (different saddr) tries to connect to the same local ports. XDP must drop
# all of them because the CT entries are tied to saddr=VM.4, not VM.5.
_run_scenario2_ct_spoof() {
    local mode=$1
    step "시나리오 2-b [mode=$mode]: CT spoof — VM.5가 container ephemeral port로 접속 (saddr=VM.5 ≠ CT saddr=VM.4)"

    info "Container /api/client-ports 조회 (REST API 우선)..."
    local ct_ports
    ct_ports=$(_get_container_ct_ports)

    if [[ -z "$ct_ports" ]]; then
        info "포트 없음; 5초 대기 후 재시도..."
        sleep 5
        ct_ports=$(_get_container_ct_ports)
    fi

    if [[ -z "$ct_ports" ]]; then
        fail "시나리오 2-b [$mode] SKIP: 컨테이너→VM.4 연결 포트를 찾을 수 없음"
        SCENARIO2_CTSPOOF_RESULT[$mode]="SKIP (no CT ports found)"
        return
    fi

    info "컨테이너 ephemeral 포트: $(echo "$ct_ports" | tr '\n' ' ')"

    local all_blocked=true
    local total_tested=0 total_connected=0

    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        total_tested=$((total_tested + 1))

        # Reset attacker stats for a clean per-port result
        curl -fsS -X POST "http://$ATTACKER_IP:8001/api/reset" &>/dev/null || true

        info "  VM.5 → container:$port (3 attempts, saddr=VM.5 ≠ CT saddr=VM.4)..."
        curl -fsS -X POST "http://$ATTACKER_IP:8001/api/attack" \
            -H 'Content-Type: application/json' \
            -d "{\"target\":\"$CONTAINER_IP\",\"port\":$port,\"count\":3,\"timeout\":2.0}" \
            &>/dev/null || true

        # Poll until attack completes (3 × 2s timeout + margin)
        local waited=0
        while [[ $waited -lt 20 ]]; do
            sleep 2; waited=$((waited + 2))
            local running
            running=$(curl -fsS --max-time 2 "http://$ATTACKER_IP:8001/api/attack/status" 2>/dev/null \
                | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('running',True))" \
                2>/dev/null || echo True)
            [[ "$running" == "False" ]] && break
        done

        local status_json connected_cnt timeout_cnt
        status_json=$(curl -fsS --max-time 3 "http://$ATTACKER_IP:8001/api/attack/status" 2>/dev/null || echo '{}')
        connected_cnt=$(_json_field "$status_json" "connected")
        timeout_cnt=$(  _json_field "$status_json" "timeout")
        info "  port $port: connected=$connected_cnt timeout=$timeout_cnt"

        if [[ "$connected_cnt" -gt 0 ]]; then
            all_blocked=false
            total_connected=$((total_connected + connected_cnt))
            fail "  port $port: ${connected_cnt} connection(s) succeeded — CT 5-tuple check FAILED!"
        else
            pass "  port $port: XDP_DROP confirmed (timeout=$timeout_cnt)"
        fi
    done <<< "$ct_ports"

    if [[ "$total_tested" -eq 0 ]]; then
        fail "시나리오 2-b [$mode] SKIP: 테스트할 포트 없음"
        SCENARIO2_CTSPOOF_RESULT[$mode]="SKIP (no ports to test)"
    elif $all_blocked; then
        pass "시나리오 2-b [$mode] PASS: ${total_tested}개 포트 모두 차단 — CT 5-tuple 특이성 확인"
        SCENARIO2_CTSPOOF_RESULT[$mode]="PASS (blocked=$total_tested ports)"
    else
        fail "시나리오 2-b [$mode] FAIL: ${total_connected}개 연결 성공 — CT spoof 가능!"
        SCENARIO2_CTSPOOF_RESULT[$mode]="FAIL (connected=$total_connected)"
    fi
}

# ── 시나리오 2-c: VM.5 → container IP 스푸핑 (saddr=TARGET_IP 위장) ──────────
# VM.5가 원시 소켓으로 saddr=TARGET_IP(192.168.100.4)를 위조한 TCP SYN을 전송.
# XDP CT 테이블에 일치하는 5-tuple이 없으므로 XDP_DROP 이어야 한다.
# attacker.py는 root(CAP_NET_RAW)로 동작 중이어야 원시 소켓이 허용된다.
_run_scenario2_ip_spoof() {
    local mode=$1
    step "시나리오 2-c [mode=$mode]: IP 스푸핑 — VM.5가 saddr=$TARGET_IP 위조 SYN 전송"

    # 스푸핑 전 컨테이너 서버 수신 건수 스냅샷
    local server_before
    server_before=$(_json_field "$(_capi /api/server-stats)" "total")
    info "스푸핑 전 컨테이너 서버 수신 건수: $server_before"

    # attacker 초기화
    curl -fsS -X POST "http://$ATTACKER_IP:8001/api/reset" &>/dev/null || true

    info "VM.5가 saddr=$TARGET_IP 위조 SYN을 컨테이너($CONTAINER_IP:$CONTAINER_PORT)에 10회 전송..."
    local spoof_resp
    spoof_resp=$(curl -fsS -X POST "http://$ATTACKER_IP:8001/api/spoof" \
        -H 'Content-Type: application/json' \
        -d "{\"spoof_src\":\"$TARGET_IP\",\"target\":\"$CONTAINER_IP\",\"port\":$CONTAINER_PORT,\"count\":10,\"interval\":0.2}" \
        2>/dev/null || echo '{"error":"unreachable"}')
    info "스푸핑 시작 응답: $spoof_resp"

    # 서비스 자체 오류(unreachable 등) 확인
    local init_error
    init_error=$(echo "$spoof_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
    if [[ -n "$init_error" ]]; then
        info "시나리오 2-c [$mode] SKIP: 스푸핑 요청 실패 — $init_error"
        SCENARIO2_IPSPOOF_RESULT[$mode]="SKIP (request failed: $init_error)"
        return
    fi

    # 완료 대기 (10회 × 0.2s = 최소 2초, 여유 15초)
    info "스푸핑 완료 대기 (최대 15초)..."
    local waited=0
    while [[ $waited -lt 15 ]]; do
        sleep 2; waited=$((waited + 2))
        local spoof_running
        spoof_running=$(curl -fsS --max-time 2 "http://$ATTACKER_IP:8001/api/spoof/status" 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('running',True))" \
            2>/dev/null || echo True)
        [[ "$spoof_running" == "False" ]] && break
    done

    # 스푸핑 결과 수집
    local spoof_status_json sent_cnt spoof_err
    spoof_status_json=$(curl -fsS --max-time 3 "http://$ATTACKER_IP:8001/api/spoof/status" 2>/dev/null || echo '{}')
    sent_cnt=$(_json_field "$spoof_status_json" "sent")
    spoof_err=$(echo "$spoof_status_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")

    if [[ -n "$spoof_err" ]]; then
        info "시나리오 2-c [$mode] SKIP: 원시 소켓 오류 — $spoof_err"
        SCENARIO2_IPSPOOF_RESULT[$mode]="SKIP (raw socket error: $spoof_err)"
        return
    fi

    info "스푸핑 전송 완료: $sent_cnt 패킷 전송"

    # 컨테이너 서버 수신 건수 변화 확인 (1초 대기로 latency 흡수)
    sleep 1
    local server_after leaked
    server_after=$(_json_field "$(_capi /api/server-stats)" "total")
    leaked=$((server_after - server_before))
    info "스푸핑 후 컨테이너 서버 수신 건수: $server_after (증가: $leaked)"

    if [[ "$leaked" -eq 0 ]]; then
        pass "시나리오 2-c [$mode] PASS: $sent_cnt개 IP 스푸핑 패킷 모두 XDP_DROP (컨테이너 미수신)"
        SCENARIO2_IPSPOOF_RESULT[$mode]="PASS (sent=$sent_cnt, leaked=0)"
    else
        fail "시나리오 2-c [$mode] FAIL: ${leaked}개 IP 스푸핑 패킷이 컨테이너에 도달 (XDP_PASS 발생!)"
        SCENARIO2_IPSPOOF_RESULT[$mode]="FAIL (leaked=$leaked)"
    fi
}

# ── 모드별 전체 실행 ─────────────────────────────────────────────────────────
_run_mode() {
    local mode=$1
    banner "IPVLAN $mode 모드 테스트"

    _start_container "$mode"
    _start_loader "$mode"

    # 컨테이너 앱 준비 대기 (podman exec 경유 — IPVLAN은 호스트→컨테이너 직접 접근 불가)
    if ! _wait_container_api 20; then
        fail "컨테이너 REST API 미응답 (mode=$mode)"
        info "컨테이너 로그:"
        sudo podman logs --tail 20 "$CONTAINER_NAME" 2>/dev/null || true
        SCENARIO1_RESULT[$mode]="SKIP (container app not ready)"
        SCENARIO2_RESULT[$mode]="SKIP (container app not ready)"
        SCENARIO2_CTSPOOF_RESULT[$mode]="SKIP (container app not ready)"
        SCENARIO2_IPSPOOF_RESULT[$mode]="SKIP (container app not ready)"
        _stop_loader
        _stop_container
        return
    fi
    pass "컨테이너 앱 준비 완료 (mode=$mode)"

    _dump_ct_map
    _run_scenario1 "$mode"

    # 시나리오 2/2-b/2-c: 모든 모드에서 실행 (L3/L3s 실패 허용)
    _run_scenario2 "$mode"
    _run_scenario2_ct_spoof "$mode"
    _run_scenario2_ip_spoof "$mode"
    _dump_ct_map

    _stop_loader
    _stop_container
}

# ── 결과 JSON 저장 ───────────────────────────────────────────────────────────
_save_results() {
    local s1_l2="${SCENARIO1_RESULT[l2]:-N/A}"
    local s1_l3="${SCENARIO1_RESULT[l3]:-N/A}"
    local s1_l3s="${SCENARIO1_RESULT[l3s]:-N/A}"
    local s2_l2="${SCENARIO2_RESULT[l2]:-N/A}"
    local s2_l3="${SCENARIO2_RESULT[l3]:-N/A}"
    local s2_l3s="${SCENARIO2_RESULT[l3s]:-N/A}"
    local s2b_l2="${SCENARIO2_CTSPOOF_RESULT[l2]:-N/A}"
    local s2b_l3="${SCENARIO2_CTSPOOF_RESULT[l3]:-N/A}"
    local s2b_l3s="${SCENARIO2_CTSPOOF_RESULT[l3s]:-N/A}"
    local s2c_l2="${SCENARIO2_IPSPOOF_RESULT[l2]:-N/A}"
    local s2c_l3="${SCENARIO2_IPSPOOF_RESULT[l3]:-N/A}"
    local s2c_l3s="${SCENARIO2_IPSPOOF_RESULT[l3s]:-N/A}"
    python3 - "$RESULTS_JSON" \
              "$s1_l2"  "$s1_l3"  "$s1_l3s" \
              "$s2_l2"  "$s2_l3"  "$s2_l3s" \
              "$s2b_l2" "$s2b_l3" "$s2b_l3s" \
              "$s2c_l2" "$s2c_l3" "$s2c_l3s" <<'PYEOF'
import sys, json
out, s1l2, s1l3, s1l3s, s2l2, s2l3, s2l3s, s2bl2, s2bl3, s2bl3s, s2cl2, s2cl3, s2cl3s = sys.argv[1:]
results = {
    'l2':  {'scenario1': s1l2,  'scenario2': s2l2,  'scenario2b_ct_spoof': s2bl2,  'scenario2c_ip_spoof': s2cl2},
    'l3':  {'scenario1': s1l3,  'scenario2': s2l3,  'scenario2b_ct_spoof': s2bl3,  'scenario2c_ip_spoof': s2cl3},
    'l3s': {'scenario1': s1l3s, 'scenario2': s2l3s, 'scenario2b_ct_spoof': s2bl3s, 'scenario2c_ip_spoof': s2cl3s},
}
with open(out, 'w') as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f'결과 저장: {out}')
PYEOF
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

banner "Auto_XDP IPVLAN Stateful Firewall Test Suite"
echo "  날짜:      $(date)"
echo "  Host:      192.168.100.3 (eth1)"
echo "  Container: $CONTAINER_IP (IPVLAN on $HOST_IFACE)"
echo "  VM.4:      $TARGET_IP (target server)"
echo "  VM.5:      $ATTACKER_IP (attacker)"

# ── 사전 검사 ────────────────────────────────────────────────────────────────
step "사전 조건 확인"
[[ -f "$LOADER_BIN"    ]] || { fail "로더 바이너리 없음: $LOADER_BIN  →  'make all' 먼저 실행"; exit 1; }
[[ -f "$XDP_BPF_OBJ"  ]] || { fail "XDP BPF 오브젝트 없음: $XDP_BPF_OBJ  →  'make bpf' 먼저 실행"; exit 1; }
[[ -f "$TC_BPF_OBJ"   ]] || { fail "TC BPF 오브젝트 없음: $TC_BPF_OBJ  →  'make bpf' 먼저 실행"; exit 1; }
command -v bpftool &>/dev/null \
    && info "bpftool 사용 가능: $(bpftool version 2>/dev/null | head -1)" \
    || info "bpftool 미설치 — CT 맵 상세 덤프 불가 (테스트 결과에는 영향 없음)"
pass "바이너리 확인 완료"

# ── Ansible 배포 ─────────────────────────────────────────────────────────────
# root 권한으로 실행될 때 geonmo의 GSSAPI 크리덴셜이 없을 수 있으므로:
# --skip-ansible 플래그 또는 서비스 이미 실행 중인 경우 건너뜀
if $SKIP_ANSIBLE; then
    info "Ansible 배포 건너뜀 (--skip-ansible 플래그)"
else
    step "Ansible: VM.4/VM.5 컴포넌트 배포"
    # 먼저 현재 사용자로 ansible 시도, 실패 시 sudo -u geonmo 시도
    if ! ansible-playbook \
                     -i "$SCRIPT_DIR/ansible/inventory.ini" \
                     "$SCRIPT_DIR/ansible/playbook.yml" \
                     --timeout 60 2>&1; then
        info "직접 ansible 실패 — sudo -u geonmo 로 재시도..."
        if ! sudo -u geonmo -E ansible-playbook \
                         -i "$SCRIPT_DIR/ansible/inventory.ini" \
                         "$SCRIPT_DIR/ansible/playbook.yml" \
                         --timeout 60 2>&1; then
            info "Ansible 배포 실패 — 기존 원격 서비스 헬스 체크로 대체..."
            _wait_http "http://$TARGET_IP:9090/api/health"   5 \
                && _wait_http "http://$ATTACKER_IP:8001/api/health" 5 \
                || { fail "Ansible 배포 실패 + 서비스 미응답. VM.4/VM.5 상태를 확인하세요."; exit 1; }
            info "기존 서비스 응답 중 — Ansible 스킵하고 계속 진행"
        fi
    fi
fi

step "원격 서비스 헬스 체크"
_wait_http "http://$TARGET_IP:9090/api/health"   15 || { fail "VM.4 target server 미응답"; exit 1; }
_wait_http "http://$ATTACKER_IP:8001/api/health" 15 || { fail "VM.5 attacker 미응답";     exit 1; }
pass "VM.4 target server OK"
pass "VM.5 attacker OK"

# ── 컨테이너 이미지 빌드 ─────────────────────────────────────────────────────
_build_image

# ── 시나리오 3: IPVLAN 모드별 비교 ──────────────────────────────────────────
# 각 모드에서 시나리오 1+2 실행
for mode in l2 l3 l3s; do
    _run_mode "$mode"
done

# ── 최종 결과 요약 ────────────────────────────────────────────────────────────
banner "최종 테스트 결과 요약"
printf "%-6s  %-38s  %-28s  %-28s  %-28s\n" \
    "모드" "시1 (egress stateful)" "시2 (inbound drop)" "시2-b (CT spoof)" "시2-c (IP spoof)"
printf "%-6s  %-38s  %-28s  %-28s  %-28s\n" \
    "──────" "──────────────────────────────────────" "────────────────────────────" "────────────────────────────" "────────────────────────────"
for mode in l2 l3 l3s; do
    printf "%-6s  %-38s  %-28s  %-28s  %-28s\n" \
        "$mode" \
        "${SCENARIO1_RESULT[$mode]:-N/A}" \
        "${SCENARIO2_RESULT[$mode]:-N/A}" \
        "${SCENARIO2_CTSPOOF_RESULT[$mode]:-N/A}" \
        "${SCENARIO2_IPSPOOF_RESULT[$mode]:-N/A}"
done

_save_results

echo ""
info "테스트 결과 JSON: $RESULTS_JSON"
info "로더 로그:        /tmp/ct-loader-{l2,l3,l3s}.log"
info "tcp_ct4 실시간 확인: sudo bpftool map dump pinned /sys/fs/bpf/auto_xdp/tcp_ct4"
