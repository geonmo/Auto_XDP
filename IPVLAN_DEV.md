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
  
      테스트 결과: L2/L3/L3s × 시나리오1(egress stateful) + 시나리오2(inbound drop) = 전 모드 PASS

      ---
      진행 중 / 다음 세션

      tests/ipvlan/run_tests.sh 수정 (부분 완료)
      - 시나리오 2, 2-b를 L2 전용으로 변경 (_run_mode에 if [[ "$mode" == "l2" ]] 조건 추가)
      - _get_container_ct_ports(): 컨테이너 /proc/net/tcp 파싱으로 VM.4 연결 ephemeral 포트 추출
      - _run_scenario2_ct_spoof(): VM.5가 해당 포트로 접속 시도 → XDP_DROP 확인 (CT 5-tuple 특이성 검증)
      - _save_results(), 요약 테이블: SCENARIO2_CTSPOOF_RESULT 컬럼 추가
      - 문법 체크 통과 (bash -n OK), 실제 테스트 실행은 미완료
    
      미착수 항목
      - IP 스푸핑 테스트 (attacker.py에 raw socket /api/spoof 엔드포인트 추가 필요, CAP_NET_RAW 필요)
      - Auto_XDP permanent add/del, exclude port 명령으로 stateless 포트 차단 설정 점검

