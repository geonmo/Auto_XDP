// cmd/xdp_detach/main.go — eth1에 남아있는 BPF XDP link를 강제 제거
// bpftool 없이 cilium/ebpf link.Iterator API로 XDP link를 닫는다.
//
// 사용: sudo ./xdp_detach [iface]   (기본: eth1)

package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
)

func main() {
	iface := "eth1"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	nic, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("인터페이스 '%s' 조회 실패: %v", iface, err)
	}
	targetIfindex := uint32(nic.Index)
	fmt.Printf("[info] %s (ifindex=%d) 의 XDP BPF link 탐색...\n", iface, targetIfindex)

	found := false
	it := new(link.Iterator)
	for it.Next() {
		lnk := it.Take() // Iterator 소유권 이전 (Next 호출 후에도 유효)

		info, err := lnk.Info()
		if err != nil {
			lnk.Close()
			continue
		}

		if info.Type != link.XDPType {
			lnk.Close()
			continue
		}

		xdpInfo := info.XDP()
		if xdpInfo == nil || xdpInfo.Ifindex != targetIfindex {
			lnk.Close()
			continue
		}

		fmt.Printf("[info] XDP link 발견: ID=%d, ifindex=%d → 제거 중...\n",
			it.ID, xdpInfo.Ifindex)
		if err := lnk.Close(); err != nil {
			log.Printf("[warn] link close 실패: %v", err)
		} else {
			fmt.Printf("[ok] XDP link 제거 완료\n")
			found = true
		}
	}
	if err := it.Err(); err != nil {
		log.Printf("[warn] link 순회 오류: %v", err)
	}

	if !found {
		fmt.Printf("[info] %s에 BPF XDP link 없음 (이미 제거됨)\n", iface)
	}
}
