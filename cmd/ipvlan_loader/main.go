// cmd/ipvlan_loader/main.go — Podman IPVLAN 컨테이너 Egress Stateful 추적기
//
// Auto_XDP의 xdp_firewall + tc_flow_track BPF 프로그램을 사용하여
// IPVLAN 컨테이너에 대한 stateful egress 방화벽을 구현한다.
//
// ── 동작 흐름 ─────────────────────────────────────────────────────────────
//  1. xdp_firewall.bpf.o 로드 → protected_ipv4 맵에 컨테이너 IP 등록
//  2. 호스트 NIC(eth1)에 xdp_port_whitelist XDP 프로그램 attach
//  3. tc_flow_track.bpf.o 로드 (tcp_ct4/udp_ct4 등 맵은 XDP 컬렉션 재사용)
//  4. 컨테이너 PID로 netns 진입 → 슬레이브 NIC egress에 tc_egress_track attach
//  5. SIGTERM 수신 시 TC → XDP 순으로 detach
//
// ── 빌드 ──────────────────────────────────────────────────────────────────
//  make all  (Auto_XDP 루트에서)
//
// ── 실행 (root 필요) ──────────────────────────────────────────────────────
//  PID=$(podman inspect --format '{{.State.Pid}}' <컨테이너명>)
//  sudo ./ipvlan_loader -iface eth1 -pid $PID \
//       -container-ip 192.168.100.10 [-xdp-mode generic|driver] [-pin-map] [-dump]

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type tcAttachInfo struct {
	containerPID   int
	ifaceIndex     int
	ifaceName      string
	filterPriority uint16
}

func main() {
	ifaceName := flag.String("iface", "eth1",
		"호스트 물리 NIC 이름 (XDP attach 대상)")
	containerPID := flag.Int("pid", 0,
		"컨테이너 PID (netns 진입용, 필수)")
	containerIface := flag.String("container-iface", "eth0",
		"컨테이너 내부 NIC 이름 (TC egress attach 대상)")
	xdpObjPath := flag.String("xdp-obj", "xdp_firewall.bpf.o",
		"XDP BPF 오브젝트 파일 경로")
	tcObjPath := flag.String("tc-obj", "tc_flow_track.bpf.o",
		"TC BPF 오브젝트 파일 경로")
	xdpMode := flag.String("xdp-mode", "generic",
		"XDP attach 모드: generic(SKB) | driver(native)")
	pinMap := flag.Bool("pin-map", false,
		"CT 맵을 /sys/fs/bpf/auto_xdp/ 에 pin (디버깅용)")
	dumpOnExit := flag.Bool("dump", false,
		"종료 시 CT 맵 내용 출력")
	containerIPFlag := flag.String("container-ip", "",
		"CT 필터를 적용할 컨테이너 IPv4 주소 (쉼표 구분)")
	flag.Parse()

	if *containerPID == 0 {
		log.Fatal("[fatal] -pid 는 필수 인자입니다.")
	}

	// ── XDP BPF Collection 로드 ──────────────────────────────────────────
	log.Printf("[info] XDP BPF 로드: %s", *xdpObjPath)
	xdpSpec, err := ebpf.LoadCollectionSpec(*xdpObjPath)
	if err != nil {
		log.Fatalf("[fatal] XDP CollectionSpec 로드 실패: %v", err)
	}
	xdpColl, err := ebpf.NewCollection(xdpSpec)
	if err != nil {
		log.Fatalf("[fatal] XDP Collection 생성 실패: %v\n  → root 권한 및 커널 >= 5.7 필요", err)
	}
	defer xdpColl.Close()

	xdpProg := xdpColl.Programs["xdp_port_whitelist"]
	if xdpProg == nil {
		log.Fatal("[fatal] 'xdp_port_whitelist' 프로그램을 찾을 수 없습니다.")
	}

	// ── protected_ipv4 맵에 컨테이너 IP 등록 ──────────────────────────────
	protectedV4Map := xdpColl.Maps["protected_ipv4"]
	if protectedV4Map == nil {
		log.Fatal("[fatal] 'protected_ipv4' 맵을 찾을 수 없습니다.")
	}
	if *containerIPFlag == "" {
		log.Printf("[warn] -container-ip 미지정: CT 필터 비활성 (모든 TCP/UDP XDP_PASS)")
	} else {
		for _, ipStr := range strings.Split(*containerIPFlag, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			parsed := net.ParseIP(ipStr)
			if parsed == nil {
				log.Printf("[warn] 유효하지 않은 IP 무시: %s", ipStr)
				continue
			}
			ip4 := parsed.To4()
			if ip4 == nil {
				log.Printf("[warn] IPv6 주소는 현재 미지원: %s", ipStr)
				continue
			}
			var keyBytes [4]byte
			copy(keyBytes[:], ip4)
			var val uint8 = 1
			if err := protectedV4Map.Put(keyBytes, val); err != nil {
				log.Printf("[warn] protected_ipv4 업데이트 실패 (%s): %v", ipStr, err)
			} else {
				log.Printf("[info] 보호 IP 등록: %s", ipStr)
			}
		}
	}

	// ── XDP runtime cfg: local subnet bogon bypass ──────────────────────
	if err := setLocalSubnet4(xdpColl, *ifaceName); err != nil {
		log.Printf("[warn] local subnet bogon bypass setup failed: %v", err)
	}

	// ── 맵 Pin (선택) ────────────────────────────────────────────────────
	const pinDir = "/sys/fs/bpf/auto_xdp"
	if *pinMap {
		if err := os.MkdirAll(pinDir, 0700); err != nil {
			log.Printf("[warn] pin 디렉터리 생성 실패: %v", err)
		} else {
			for _, mapName := range []string{"tcp_ct4", "udp_ct4"} {
				m := xdpColl.Maps[mapName]
				if m == nil {
					continue
				}
				pinPath := pinDir + "/" + mapName
				_ = os.Remove(pinPath)
				if err := m.Pin(pinPath); err != nil {
					log.Printf("[warn] %s pin 실패: %v", mapName, err)
				} else {
					log.Printf("[info] %s pinned → %s", mapName, pinPath)
				}
			}
			defer func() {
				for _, mapName := range []string{"tcp_ct4", "udp_ct4"} {
					_ = os.Remove(pinDir + "/" + mapName)
				}
				_ = os.Remove(pinDir)
			}()
		}
	}

	// ── XDP Ingress attach (호스트 NIC) ───────────────────────────────────
	hostLink, err := netlink.LinkByName(*ifaceName)
	if err != nil {
		log.Fatalf("[fatal] 호스트 인터페이스 '%s' 조회 실패: %v", *ifaceName, err)
	}

	var xdpFlags link.XDPAttachFlags
	switch *xdpMode {
	case "driver", "native":
		xdpFlags = link.XDPDriverMode
		log.Printf("[info] XDP driver(native) 모드")
	default:
		xdpFlags = link.XDPGenericMode
		log.Printf("[info] XDP generic(SKB) 모드")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: hostLink.Attrs().Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("[fatal] XDP attach 실패 (iface=%s): %v", *ifaceName, err)
	}
	log.Printf("[info] XDP ingress attach 완료: %s", *ifaceName)

	// ── TC BPF Collection 로드 (맵 공유) ──────────────────────────────────
	log.Printf("[info] TC BPF 로드: %s", *tcObjPath)
	tcSpec, err := ebpf.LoadCollectionSpec(*tcObjPath)
	if err != nil {
		xdpLink.Close()
		log.Fatalf("[fatal] TC CollectionSpec 로드 실패: %v", err)
	}

	// XDP 컬렉션의 CT 맵을 TC 컬렉션이 재사용 — 같은 커널 맵 객체 공유
	mapReplacements := map[string]*ebpf.Map{}
	for _, name := range []string{"tcp_ct4", "tcp_ct6", "udp_ct4", "udp_ct6", "sctp_conntrack"} {
		if m := xdpColl.Maps[name]; m != nil {
			mapReplacements[name] = m
		}
	}
	tcColl, err := ebpf.NewCollectionWithOptions(tcSpec, ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	})
	if err != nil {
		xdpLink.Close()
		log.Fatalf("[fatal] TC Collection 생성 실패: %v", err)
	}
	defer tcColl.Close()

	tcProg := tcColl.Programs["tc_egress_track"]
	if tcProg == nil {
		xdpLink.Close()
		log.Fatal("[fatal] 'tc_egress_track' 프로그램을 찾을 수 없습니다.")
	}

	// ── TC Egress attach (container netns) ────────────────────────────────
	tcInfo, err := attachTCInContainerNetns(*containerPID, *containerIface, tcProg)
	if err != nil {
		xdpLink.Close()
		log.Fatalf("[fatal] TC egress attach failed (container): %v", err)
	}
	log.Printf("[info] TC egress attached (container): PID=%d iface=%s", *containerPID, *containerIface)

	// ── TC Egress attach (host NIC) — tracks host-initiated connections ───
	// Allows XDP to pass reply traffic for connections the host itself started
	// (e.g. management API calls to VMs on the same subnet).
	hostTCInfo, err := attachTCOnHostIface(*ifaceName, tcProg)
	if err != nil {
		log.Printf("[warn] TC egress attach on host iface %s failed: %v", *ifaceName, err)
		hostTCInfo = nil
	} else {
		log.Printf("[info] TC egress attached (host): iface=%s", *ifaceName)
	}

	// ── Wait for shutdown signal ──────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("[info] running... (send SIGTERM to stop)")
	<-sigCh
	log.Printf("[info] shutdown signal received, cleaning up...")

	if *dumpOnExit {
		dumpCTMaps(xdpColl)
	}

	if hostTCInfo != nil {
		if err := detachTCOnHostIface(hostTCInfo); err != nil {
			log.Printf("[warn] TC detach failed (host): %v", err)
		} else {
			log.Printf("[info] TC egress detached (host)")
		}
	}

	if err := detachTCInContainerNetns(tcInfo); err != nil {
		log.Printf("[warn] TC detach failed (container): %v", err)
	} else {
		log.Printf("[info] TC egress detached (container)")
	}

	if err := xdpLink.Close(); err != nil {
		log.Printf("[warn] XDP detach failed: %v", err)
	} else {
		log.Printf("[info] XDP ingress detached")
	}

	log.Printf("[info] shutdown complete.")
}

// attachTCOnHostIface attaches tc_egress_track to the host NIC egress (no netns switch).
// This lets XDP accept reply traffic for connections the host itself initiates.
func attachTCOnHostIface(ifaceName string, prog *ebpf.Program) (*tcAttachInfo, error) {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("host interface %s not found: %w", ifaceName, err)
	}
	ifaceIdx := iface.Attrs().Index

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIdx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("clsact qdisc failed on %s: %w", ifaceName, err)
	}

	const filterPriority = 2 // priority 2 to avoid conflict with container's priority 1
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIdx,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, filterPriority),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           prog.FD(),
		Name:         "ipvlan_host_ct_egress",
		DirectAction: true,
	}
	// Remove stale filter from a previous crash/SIGKILL before attaching.
	stale := filter.FilterAttrs
	_ = netlink.FilterDel(&netlink.BpfFilter{FilterAttrs: stale})
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("TC filter add failed on %s: %w", ifaceName, err)
	}

	return &tcAttachInfo{
		containerPID:   -1, // sentinel: host netns, no PID lookup
		ifaceIndex:     ifaceIdx,
		ifaceName:      ifaceName,
		filterPriority: filterPriority,
	}, nil
}

// detachTCOnHostIface removes the TC egress filter from the host NIC.
func detachTCOnHostIface(info *tcAttachInfo) error {
	iface, err := netlink.LinkByIndex(info.ifaceIndex)
	if err != nil {
		return fmt.Errorf("host interface index %d not found: %w", info.ifaceIndex, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, info.filterPriority),
			Protocol:  unix.ETH_P_ALL,
			Priority:  info.filterPriority,
		},
	}
	if err := netlink.FilterDel(filter); err != nil && err != syscall.ENOENT {
		log.Printf("[warn] TC filter del failed on %s: %v", info.ifaceName, err)
	}
	return nil
}

func attachTCInContainerNetns(pid int, ifaceName string, prog *ebpf.Program) (*tcAttachInfo, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("호스트 netns 획득 실패: %w", err)
	}
	defer hostNS.Close()

	containerNS, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("컨테이너 netns 획득 실패 (PID=%d): %w", pid, err)
	}
	defer containerNS.Close()

	if err := netns.Set(containerNS); err != nil {
		return nil, fmt.Errorf("컨테이너 netns 전환 실패: %w", err)
	}
	defer func() {
		if err := netns.Set(hostNS); err != nil {
			log.Printf("[error] 호스트 netns 복귀 실패: %v", err)
		}
	}()

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("컨테이너 인터페이스 '%s' 조회 실패: %w", ifaceName, err)
	}
	ifaceIdx := iface.Attrs().Index

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIdx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("clsact qdisc 생성 실패: %w", err)
	}

	const filterPriority = 1
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIdx,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, filterPriority),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           prog.FD(),
		Name:         "ipvlan_ct_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("TC BPF filter 생성 실패: %w", err)
	}

	return &tcAttachInfo{
		containerPID:   pid,
		ifaceIndex:     ifaceIdx,
		ifaceName:      ifaceName,
		filterPriority: filterPriority,
	}, nil
}

func detachTCInContainerNetns(info *tcAttachInfo) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("호스트 netns 획득 실패: %w", err)
	}
	defer hostNS.Close()

	containerNS, err := netns.GetFromPid(info.containerPID)
	if err != nil {
		return fmt.Errorf("컨테이너 netns 획득 실패: %w", err)
	}
	defer containerNS.Close()

	if err := netns.Set(containerNS); err != nil {
		return fmt.Errorf("컨테이너 netns 전환 실패: %w", err)
	}
	defer func() { _ = netns.Set(hostNS) }()

	iface, err := netlink.LinkByIndex(info.ifaceIndex)
	if err != nil {
		return fmt.Errorf("컨테이너 인터페이스(index=%d) 조회 실패: %w", info.ifaceIndex, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, info.filterPriority),
			Protocol:  unix.ETH_P_ALL,
			Priority:  info.filterPriority,
		},
	}
	if err := netlink.FilterDel(filter); err != nil && err != syscall.ENOENT {
		log.Printf("[warn] TC filter 삭제 실패: %v", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil && err != syscall.ENOENT {
		log.Printf("[warn] clsact qdisc 삭제 실패: %v", err)
	}

	return nil
}

// xdpRuntimeCfg mirrors struct xdp_runtime_cfg in bpf/include/common.h.
// Fields must match the C struct layout exactly (little-endian u64/u32,
// big-endian [4]byte for __be32 fields).
type xdpRuntimeCfg struct {
	TCPTimeoutNs      uint64
	UDPTimeoutNs      uint64
	CTRefreshNs       uint64
	ICMPTokenMax      uint64
	ICMPNsPerToken    uint64
	UDPGlobalWindowNs uint64
	RateWindowNs      uint64
	SYNTimeoutNs      uint64
	CfgFlags          uint32
	Pad               uint32
	LocalSubnet4Addr  [4]byte // __be32: network address, 0 = disabled
	LocalSubnet4Mask  [4]byte // __be32: subnet mask,     0 = disabled
}

// setLocalSubnet4 reads the parent interface subnet and stores it in the
// xdp_runtime_cfg map so the BPF bogon filter can skip traffic from that subnet.
func setLocalSubnet4(coll *ebpf.Collection, ifaceName string) error {
	m := coll.Maps["xdp_runtime_cfg"]
	if m == nil {
		return fmt.Errorf("xdp_runtime_cfg map not found")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface lookup failed: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("interface address lookup failed: %w", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		network := ip4.Mask(ipnet.Mask)
		var key uint32 = 0
		var cfg xdpRuntimeCfg
		_ = m.Lookup(&key, &cfg)
		copy(cfg.LocalSubnet4Addr[:], network[:4])
		copy(cfg.LocalSubnet4Mask[:], []byte(ipnet.Mask)[:4])
		if err := m.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update xdp_runtime_cfg: %w", err)
		}
		ones, _ := ipnet.Mask.Size()
		log.Printf("[info] local subnet bogon bypass enabled: %s/%d", network, ones)
		return nil
	}
	return fmt.Errorf("no IPv4 address on interface %s", ifaceName)
}

// dumpCTMaps: tcp_ct4, udp_ct4 맵 내용 출력
// ct_key_v4 레이아웃 (12바이트):
//
//	[0-1]  sport (big-endian)
//	[2-3]  dport (big-endian)
//	[4-7]  saddr (big-endian)
//	[8-11] daddr (big-endian)
func dumpCTMaps(coll *ebpf.Collection) {
	for _, mapName := range []string{"tcp_ct4", "udp_ct4"} {
		m := coll.Maps[mapName]
		if m == nil {
			continue
		}
		fmt.Printf("\n── %s 덤프 ─────────────────────────────────────\n", mapName)
		fmt.Printf("%-21s %-21s %-6s %-6s %s\n", "SRC_IP", "DST_IP", "SPORT", "DPORT", "LAST_SEEN_NS")
		fmt.Println("────────────────────────────────────────────────────────────")

		var key [12]byte
		var value uint64
		count := 0
		iter := m.Iterate()
		for iter.Next(&key, &value) {
			sport := binary.BigEndian.Uint16(key[0:2])
			dport := binary.BigEndian.Uint16(key[2:4])
			src := net.IP(key[4:8]).String()
			dst := net.IP(key[8:12]).String()
			fmt.Printf("%-21s %-21s %-6d %-6d %d\n", src, dst, sport, dport, value)
			count++
		}
		if err := iter.Err(); err != nil {
			log.Printf("[warn] %s 순회 오류: %v", mapName, err)
		}
		fmt.Printf("총 %d개 항목\n", count)
	}
}
