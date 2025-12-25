package envdetect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

type Network struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	SrcIP     string `json:"src_ip"`
}

func DetectLocalNetworks() ([]Network, error) {
	cmd := exec.Command("ip", "-j", "addr")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var data []struct {
		Ifname string `json:"ifname"`
		Addr   []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}

	if err := json.Unmarshal(out.Bytes(), &data); err != nil {
		return nil, err
	}

	var nets []Network
	for _, iface := range data {
		for _, a := range iface.Addr {
			if a.Family != "inet" {
				continue
			}
			cidr := fmt.Sprintf("%s/%d", a.Local, a.Prefix)
			nets = append(nets, Network{
				Interface: iface.Ifname,
				CIDR:      cidr,
				SrcIP:     a.Local,
			})
		}
	}

	return nets, nil
}
