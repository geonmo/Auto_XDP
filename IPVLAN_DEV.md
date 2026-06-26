2026-06-26
     
      완료된 작업
     
      bogon 필터 수정 (로컬 서브넷 우회)
      - bpf/include/common.h: xdp_runtime_cfg에 local_subnet4_addr, local_subnet4_mask (__be32) 필드 추가 (구조체 72→80 bytes)
      - bpf/include/trust_acl.h: saddr_in_local_net4() 헬퍼 추가 — 로컬 서브넷 출발지 IP는 bogon 필터 건너뜀
      - bpf/xdp_firewall.c: bogon 체크 앞에 saddr_in_local_net4() 조건 추가
      - cmd/ipvlan_loader/main.go: setLocalSubnet4() 함수로 eth1 서브넷 읽어 BPF 맵에 기록
     
      호스트 TCP 연결 CT 등록 (TC dual-attach)
      - cmd/ipvlan_loader/main.go: attachTCOnHostIface() / detachTCOnHostIface() 추가
      - TC egress를 컨테이너 netns eth0 뿐만 아니라 호스트 eth1에도 부착
      - SIGKILL 후 stale filter 처리: FilterDel 선행 후 FilterAdd

      tc_flow_track.c 수정
      - tcp_ct6, udp_ct6 max_entries를 65536 → 196608 (CT_MAP_MAX_ENTRIES_V6)으로 수정 — MapReplacements 크기 불일치 수정

      xdp_detach 유틸리티
      - cmd/xdp_detach/main.go: link.Iterator로 커널 BPF link 순회, 대상 ifindex의 XDP link fd 강제 해제

      docs/IPVLAN.md
      - 아키텍처, 빌드, XDP 강제 제거 방법(4가지), 트러블슈팅 작성

      테스트 코드 완성 (tests/ipvlan/)
      - attacker.py: IP 스푸핑용 /api/spoof 엔드포인트 추가
        - raw IPv4 TCP SYN 패킷 조립 (_build_spoofed_syn, _inet_cksum)
        - _spoof_worker: CAP_NET_RAW 없으면 즉시 에러 반환 (fail-safe)
        - /api/spoof/status, /api/reset에 spoof_state 통합
      - container_app.py: ephemeral 포트 추적 강화
        - _PortTrackingHTTPConn: HTTP 연결 시 로컬 포트 자동 캡처
        - /api/client-ports: 최근 50개 ephemeral 포트 반환 (TIME_WAIT 만료 후에도 유효)
      - run_tests.sh: 4개 시나리오로 확장
        - _run_scenario2_ct_spoof(): CT 5-tuple 특이성 검증 (시나리오 2-b)
        - _run_scenario2_ip_spoof(): IP 스푸핑 차단 검증 (시나리오 2-c)
        - _get_container_ct_ports(): REST API 우선, /proc/net/tcp fallback
        - _get_ct_entries(): bpftool 없을 때 핀 파일 존재 여부로 대체
        - 시나리오 2/2-b/2-c를 L2 전용으로 제한 (L3/L3s는 SKIP)
        - --skip-ansible 플래그 추가 (root 실행 시 GSSAPI 우회)
        - _save_results(): scenario2c_ip_spoof 컬럼 추가
        - 요약 테이블: 4컬럼으로 확장
      - ansible/roles/attacker/templates/ct-attacker.service.j2:
        - User=root 추가 → CAP_NET_RAW 허용 (원시 소켓 스푸핑에 필요)

      ---
      테스트 결과 (2026-06-26 07:31:21 UTC, test_results_20260626_073121.json)

      모드   시나리오1 (egress)                    시나리오2 (inbound)    시나리오2-b (CT spoof)     시나리오2-c (IP spoof)
      ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
      L2     PASS (success=4, target=4)            PASS (dropped=10)      PASS (blocked=10 ports)    PASS (sent=10, leaked=0)
      L3     PASS (success=4, target=4)            SKIP (L2 only)         SKIP (L2 only)             SKIP (L2 only)
      L3s    PASS (success=4, target=4)            SKIP (L2 only)         SKIP (L2 only)             SKIP (L2 only)

      전체 PASS (L2 기준 4/4 시나리오)
      실행 시간: 약 2분 (L2: ~2분, L3/L3s: 각 ~20초)

      ---
      미착수 항목

      - Auto_XDP permanent add/del, exclude port 명령으로 stateless 포트 차단 설정 점검
