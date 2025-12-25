package envdetect

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type NetInfo struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	SrcIP     string `json:"src_ip"`
}

func DetectNetInfo() (NetInfo, error) {
	// берём конкретно default route
	cmd := exec.Command("ip", "route", "show", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return NetInfo{}, fmt.Errorf("ip route default error: %w (%s)", err, out.String())
	}

	line := strings.TrimSpace(out.String())
	// пример:
	// default via 172.20.10.1 dev wlp0s20f3 proto dhcp metric 600
	parts := strings.Fields(line)

	var gw, dev string
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "via" {
			gw = parts[i+1]
		}
		if parts[i] == "dev" {
			dev = parts[i+1]
		}
	}

	if dev == "" {
		return NetInfo{}, fmt.Errorf("cannot parse dev from: %s", line)
	}

	// теперь вытаскиваем src IP для этого dev
	cmd2 := exec.Command("ip", "-4", "route", "get", "1.1.1.1")
	var out2 bytes.Buffer
	cmd2.Stdout = &out2
	cmd2.Stderr = &out2
	_ = cmd2.Run()

	// пример:
	// 1.1.1.1 via 172.20.10.1 dev wlp0s20f3 src 172.20.10.3 uid 0
	line2 := strings.TrimSpace(out2.String())
	parts2 := strings.Fields(line2)
	var src string
	for i := 0; i < len(parts2)-1; i++ {
		if parts2[i] == "src" {
			src = parts2[i+1]
			break
		}
	}

	return NetInfo{
		Interface: dev,
		Gateway:   gw,
		SrcIP:     src,
	}, nil
}
