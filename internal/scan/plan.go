package scan

import (
	"fmt"
	"net"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/envdetect"
)

type ScanPlan struct {
	Targets     []string `json:"targets"`
	Ports       string   `json:"ports"`
	Engine      string   `json:"engine"`
	Interface   string   `json:"interface"`
	WaitSeconds int      `json:"wait_seconds"`
	Reason      string   `json:"reason"`
}

func (r *Runner) Plan(cfg *config.Config) (*ScanPlan, error) {
	// --- SINGLE HOST HANDLING ---
	if len(cfg.Targets) == 1 {
		t := cfg.Targets[0]

		// чистый IP (10.12.0.6)
		if ip := net.ParseIP(t); ip != nil {
			return &ScanPlan{
				Targets:     []string{t},
				Ports:       resolvePorts(cfg.Ports, "nmap"),
				Engine:      "nmap",
				Interface:   cfg.Interface,
				WaitSeconds: 1,
				Reason:      "single host",
			}, nil
		}

		// IP/32 (10.12.0.6/32)
		if _, netw, err := net.ParseCIDR(t); err == nil {
			ones, bits := netw.Mask.Size()
			if ones == bits {
				return &ScanPlan{
					Targets:     []string{t},
					Ports:       resolvePorts(cfg.Ports, "nmap"),
					Engine:      "nmap",
					Interface:   cfg.Interface,
					WaitSeconds: 1,
					Reason:      "single host (/32)",
				}, nil
			}
		}
	}

	if len(cfg.Targets) == 0 && !cfg.AutoTargets {
		return nil, fmt.Errorf("no targets specified")
	}

	// auto_targets
	targets := cfg.Targets
	if cfg.AutoTargets && len(targets) == 0 {
		ni, err := envdetect.DetectNetInfo()
		if err != nil || ni.SrcIP == "" {
			return nil, fmt.Errorf("auto target detection failed")
		}
		targets = []string{ni.SrcIP + "/24"}
	}

	dec := envdetect.Decide(targets)

	// interface
	iface := cfg.Interface
	if iface == "" {
		ifc, _ := envdetect.DetectDefaultInterface()
		iface = ifc
	}

	// wait_seconds
	wait := cfg.WaitSeconds
	if wait <= 0 {
		wait = dec.WaitSeconds
	}

	ports := resolvePorts(cfg.Ports, dec.PreferredEngine)

	return &ScanPlan{
		Targets:     targets,
		Ports:       ports,
		Engine:      dec.PreferredEngine,
		Interface:   iface,
		WaitSeconds: wait,
		Reason:      dec.Reason,
	}, nil
}
