package scan

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/L1nMay/portscanner/internal/banner"
	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/envdetect"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/masscan"
	"github.com/L1nMay/portscanner/internal/model"
	"github.com/L1nMay/portscanner/internal/nmap"
	"github.com/L1nMay/portscanner/internal/storage"
)

type Runner struct {
	cfg   *config.Config
	pg *storage.Postgres
	store *storage.Storage
	mu    sync.Mutex

	muCancel cancelState
	hub      *Hub
}

func (r *Runner) SetPostgres(pg *storage.Postgres) {
	r.pg = pg
}

func NewRunner(cfg *config.Config, store *storage.Storage) *Runner {
	r := &Runner{cfg: cfg, store: store}
	r.hub = NewHub()
	return r
}

func checkBinary(name string) error {
	_, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", name)
	}
	return nil
}

// RunOnce оставляем как “старый синхронный” вариант (можно использовать для CLI/скрипта)
func (r *Runner) RunOnce() (*model.ScanRun, []*model.ScanResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := checkBinary("nmap"); err != nil {
		return nil, nil, err
	}
	if err := checkBinary(r.cfg.MasscanPath); err != nil {
		logger.Errorf("masscan check: %v", err)
	}

	if r.cfg.AutoTargets && len(r.cfg.Targets) == 0 {
		ni, err := envdetect.DetectNetInfo()
		if err == nil && ni.SrcIP != "" {
			cidr := ni.SrcIP + "/24"
			r.cfg.Targets = []string{cidr}
			logger.Infof("Auto targets enabled: %s", cidr)
		} else {
			logger.Errorf("Auto targets failed: %v", err)
		}
	}

	if len(r.cfg.Targets) == 0 {
		return nil, nil, fmt.Errorf("no scan targets specified")
	}

	dec := envdetect.Decide(r.cfg.Targets)

	if r.cfg.Interface == "" {
		ifc, err := envdetect.DetectDefaultInterface()
		if err == nil {
			r.cfg.Interface = ifc
			logger.Infof("Auto-detected interface: %s", ifc)
		} else {
			logger.Errorf("Failed to auto-detect interface: %v", err)
		}
	}

	wait := r.cfg.WaitSeconds
	if wait <= 0 {
		wait = dec.WaitSeconds
		logger.Infof("Auto wait_seconds=%d (reason: %s)", wait, dec.Reason)
	}

	resolvedPorts := resolvePorts(r.cfg.Ports, dec.PreferredEngine)

	run := &model.ScanRun{
		ID:           fmt.Sprintf("%d", time.Now().UTC().UnixNano()),
		StartedAt:    time.Now().UTC(),
		TargetsCount: len(r.cfg.Targets),
		PortsSpec:    resolvedPorts,
		Engine:       dec.PreferredEngine,
		Notes:        dec.Reason,
	}

	engineCfg := *r.cfg
	engineCfg.Ports = resolvedPorts
	engineCfg.WaitSeconds = wait

	var (
		found      []masscan.Result
		engineUsed = dec.PreferredEngine
	)

	if dec.PreferredEngine == "masscan" {
		mr, err := masscan.Run(&engineCfg)
		if err != nil {
			logger.Errorf("masscan error: %v", err)
		}
		found = mr

		if len(found) == 0 {
			logger.Infof("masscan returned 0 results, falling back to nmap")
			engineUsed = "mixed"

			nr, err := nmap.Run(&engineCfg)
			if err != nil {
				return nil, nil, err
			}
			for _, rr := range nr {
				found = append(found, masscan.Result{
					IP:    rr.IP,
					Port:  rr.Port,
					Proto: rr.Proto,
				})
			}
		}
	} else {
		nr, err := nmap.Run(&engineCfg)
		if err != nil {
			return nil, nil, err
		}
		engineUsed = "nmap"
		for _, rr := range nr {
			found = append(found, masscan.Result{
				IP:    rr.IP,
				Port:  rr.Port,
				Proto: rr.Proto,
			})
		}
	}

	newOnes := []*model.ScanResult{}
	totalFound := 0
	newFound := 0
	seen := map[string]struct{}{}

	for _, fr := range found {
		key := fmt.Sprintf("%s:%d", fr.IP, fr.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		totalFound++

		bnr, svc, _ := banner.GrabBanner(fr.IP, fr.Port, &engineCfg)
		if svc == "" {
			svc = "unknown"
		}

		res := &model.ScanResult{
			IP:      fr.IP,
			Port:    fr.Port,
			Proto:   strings.ToLower(fr.Proto),
			Banner:  bnr,
			Service: svc,
		}

		isNew, err := r.store.UpsertResult(res)
		if err != nil {
			logger.Errorf("store upsert error for %s: %v", key, err)
			continue
		}

		if isNew {
			newFound++
			newOnes = append(newOnes, res)
		}
	}

	run.FinishedAt = time.Now().UTC()
	run.Found = totalFound
	run.NewFound = newFound
	run.Engine = engineUsed

	_ = r.store.AddScanRun(run)

	return run, newOnes, nil
}
