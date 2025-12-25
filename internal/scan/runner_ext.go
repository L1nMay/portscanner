package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/L1nMay/portscanner/internal/banner"
	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/envdetect"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/masscan"
	"github.com/L1nMay/portscanner/internal/model"
	"github.com/L1nMay/portscanner/internal/nmap"
)

/*
RunAsync — неблокирующий запуск скана
*/
func (r *Runner) RunAsync(cfg *config.Config) {
	go func() {
		_, _, _ = r.RunOnceWithContext(cfg)
	}()
}

/*
RunOnceWithContext — управляет mutex, ctx/cancel, hub
*/
func (r *Runner) RunOnceWithContext(cfg *config.Config) (*model.ScanRun, []*model.ScanResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// временно подменяем конфиг
	orig := r.cfg
	r.cfg = cfg
	defer func() { r.cfg = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	r.setCancel(cancel)
	defer r.clearCancel()

	r.hub.Publish(Progress{Percent: 5, Message: "Scan started"})

	run, newOnes, err := r.RunOnceCtx(ctx)
	if err != nil {
		// финальное событие (важно для UI)
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "Scan cancelled"
		}
		r.hub.Publish(Progress{Percent: 100, Message: msg})
		return nil, nil, err
	}

	r.hub.Publish(Progress{Percent: 100, Message: "Scan finished"})
	return run, newOnes, nil
}

/*
RunOnceCtx — ctx-aware версия RunOnce
ВАЖНО:
- без mutex (mutex берётся в RunOnceWithContext)
- masscan.RunCtx / nmap.RunCtx
- проверка ctx.Done()
- hub.Publish() по этапам
*/
func (r *Runner) RunOnceCtx(ctx context.Context) (*model.ScanRun, []*model.ScanResult, error) {
	// pre-flight cancel
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	r.hub.Publish(Progress{Percent: 10, Message: "Pre-flight checks"})

	// pre-flight
	if err := checkBinary("nmap"); err != nil {
		return nil, nil, err
	}
	if err := checkBinary(r.cfg.MasscanPath); err != nil {
		logger.Errorf("masscan check: %v", err)
	}

	// auto targets
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

	// auto interface
	if r.cfg.Interface == "" {
		ifc, err := envdetect.DetectDefaultInterface()
		if err == nil {
			r.cfg.Interface = ifc
			logger.Infof("Auto-detected interface: %s", ifc)
		} else {
			logger.Errorf("Failed to auto-detect interface: %v", err)
		}
	}

	// auto wait
	wait := r.cfg.WaitSeconds
	if wait <= 0 {
		wait = dec.WaitSeconds
		logger.Infof("Auto wait_seconds=%d (reason: %s)", wait, dec.Reason)
	}

	// resolve ports BEFORE engines
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

	r.hub.Publish(Progress{Percent: 20, Message: "Launching scan engine"})

	var (
		found      []masscan.Result
		engineUsed = dec.PreferredEngine
	)

	// ---- primary engine ----
	if dec.PreferredEngine == "masscan" {
		r.hub.Publish(Progress{Percent: 30, Message: "Running masscan"})
		mr, err := masscan.RunCtx(ctx, &engineCfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			logger.Errorf("masscan error: %v", err)
		}
		found = mr

		if len(found) == 0 {
			r.hub.Publish(Progress{Percent: 45, Message: "Masscan returned 0, fallback to nmap"})
			engineUsed = "mixed"

			nr, err := nmap.RunCtx(ctx, &engineCfg)
			if err != nil {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
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
		r.hub.Publish(Progress{Percent: 35, Message: "Running nmap"})
		nr, err := nmap.RunCtx(ctx, &engineCfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
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

	// ---- pipeline ----
	r.hub.Publish(Progress{Percent: 70, Message: "Analyzing banners & storing results"})

	newOnes := []*model.ScanResult{}
	totalFound := 0
	newFound := 0
	seen := map[string]struct{}{}

	// чтобы прогресс не “застревал” визуально
	lastTick := time.Now()

	for i, fr := range found {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

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

		// лёгкий “живой” прогресс (не спамим каждую запись)
		if time.Since(lastTick) > 700*time.Millisecond {
			lastTick = time.Now()
			p := 70
			if len(found) > 0 {
				p = 70 + int(float64(i+1)/float64(len(found))*25.0) // 70..95
			}
			r.hub.Publish(Progress{Percent: p, Message: fmt.Sprintf("Processed %d/%d", i+1, len(found))})
		}
	}

	run.FinishedAt = time.Now().UTC()
	run.Found = totalFound
	run.NewFound = newFound
	run.Engine = engineUsed

	_ = r.store.AddScanRun(run)

	r.hub.Publish(Progress{Percent: 98, Message: "Finalizing"})
	return run, newOnes, nil
}
