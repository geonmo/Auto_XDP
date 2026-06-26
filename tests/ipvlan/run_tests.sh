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
#   3. IPVLAN 모드 비교: L2 / L3 / L3s 각각에서 시나리오 1+2 반복
#
# 사전 조건:
#   make all  (Auto_XDP 루트에서)
#   VM.4, VM.5에 SSH 접속 가능 (ansible이 자동 배포)
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
declare -A SCENARIO1_RESULT SCENARIO2_RESULT

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

_dump_ct_map() {
    info "tcp_ct4 맵 내용 (핀: /sys/fs/bpf/auto_xdp/tcp_ct4):"
    sudo bpftool map dump pinned /sys/fs/bpf/auto_xdp/tcp_ct4 2>/dev/null \
        | head -30 || echo "  (맵 덤프 불가)"
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
    map_entries=$(sudo bpftool map dump pinned /sys/fs/bpf/auto_xdp/tcp_ct4 2>/dev/null | grep -c 'key' || true)
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
        pass "시나리오 1 [$mode] PASS: 컨테이너→VM.4 $success회 성공, VM.4 수신 $target_total회, CT map $map_entries 엔트리"
        SCENARIO1_RESULT[$mode]="PASS (success=$success, ct_entries=$map_entries)"
    elif [[ "$map_entries" -gt 0 && "$success" -eq 0 ]]; then
        # CT 등록은 됐지만 회신이 오지 않은 경우 — L3/L3s에서 라우팅 이슈 가능
        fail "시나리오 1 [$mode] PARTIAL: TC 등록($map_entries 엔트리) 확인, 회신 수신 실패 (라우팅 설정 필요 가능)"
        SCENARIO1_RESULT[$mode]="PARTIAL (tc_ok, routing_issue)"
    else
        fail "시나리오 1 [$mode] FAIL: success=$success map_entries=$map_entries"
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
        _stop_loader
        _stop_container
        return
    fi
    pass "컨테이너 앱 준비 완료 (mode=$mode)"

    _dump_ct_map
    _run_scenario1 "$mode"
    _run_scenario2 "$mode"
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
    python3 - "$RESULTS_JSON" \
              "$s1_l2" "$s1_l3" "$s1_l3s" \
              "$s2_l2" "$s2_l3" "$s2_l3s" <<'PYEOF'
import sys, json
out, s1l2, s1l3, s1l3s, s2l2, s2l3, s2l3s = sys.argv[1:]
results = {
    'l2':  {'scenario1': s1l2,  'scenario2': s2l2},
    'l3':  {'scenario1': s1l3,  'scenario2': s2l3},
    'l3s': {'scenario1': s1l3s, 'scenario2': s2l3s},
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
pass "바이너리 확인 완료"

# ── Ansible 배포 ─────────────────────────────────────────────────────────────
# geonmo 계정의 SSH 키로 실행 (sudo -E 로 SSH_AUTH_SOCK 유지 필요)
step "Ansible: VM.4/VM.5 컴포넌트 배포"
sudo -u geonmo -E ansible-playbook \
                 -i "$SCRIPT_DIR/ansible/inventory.ini" \
                 "$SCRIPT_DIR/ansible/playbook.yml" \
                 --timeout 60 \
    || { fail "Ansible 배포 실패. VM.4/VM.5 SSH 접속 및 인벤토리를 확인하세요."; exit 1; }

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
printf "%-8s  %-50s  %-45s\n" "모드" "시나리오1 (egress stateful)" "시나리오2 (inbound drop)"
printf "%-8s  %-50s  %-45s\n" "────────" "──────────────────────────────────────────────────" "─────────────────────────────────────────────"
for mode in l2 l3 l3s; do
    printf "%-8s  %-50s  %-45s\n" \
        "$mode" \
        "${SCENARIO1_RESULT[$mode]:-N/A}" \
        "${SCENARIO2_RESULT[$mode]:-N/A}"
done

_save_results

echo ""
info "테스트 결과 JSON: $RESULTS_JSON"
info "로더 로그:        /tmp/ct-loader-{l2,l3,l3s}.log"
info "tcp_ct4 실시간 확인: make watch-map (프로젝트 루트)"
