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
		_, err := r.RunOnceWithContext(cfg)
		if err != nil {
			logger.Errorf("async scan error: %v", err)
		}
	}()
}

/*
RunOnceWithContext — mutex + ctx/cancel + hub
*/
func (r *Runner) RunOnceWithContext(cfg *config.Config) (*model.ScanRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	orig := r.cfg
	r.cfg = cfg
	defer func() { r.cfg = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	r.setCancel(cancel)
	defer r.clearCancel()

	r.hub.Publish(Progress{Percent: 5, Message: "Scan started"})

	run, err := r.RunOnceCtx(ctx)
	if err != nil {
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "Scan cancelled"
		}
		r.hub.Publish(Progress{Percent: 100, Message: msg})
		return nil, err
	}

	r.hub.Publish(Progress{Percent: 100, Message: "Scan finished"})
	return run, nil
}

/*
RunOnceCtx — ctx-aware scan
*/
func (r *Runner) RunOnceCtx(ctx context.Context) (*model.ScanRun, error) {
	if r.pg == nil && r.store == nil {
		return nil, fmt.Errorf("no storage configured (pg=nil and store=nil)")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.hub.Publish(Progress{Percent: 10, Message: "Pre-flight checks"})

	if err := checkBinary("nmap"); err != nil {
		return nil, err
	}
	if err := checkBinary(r.cfg.MasscanPath); err != nil {
		logger.Errorf("masscan check failed: %v", err)
	}

	// auto targets
	if r.cfg.AutoTargets && len(r.cfg.Targets) == 0 {
		ni, err := envdetect.DetectNetInfo()
		if err == nil && ni.SrcIP != "" {
			cidr := ni.SrcIP + "/24"
			r.cfg.Targets = []string{cidr}
			logger.Infof("Auto targets enabled: %s", cidr)
		}
	}

	if len(r.cfg.Targets) == 0 {
		return nil, fmt.Errorf("no scan targets specified")
	}

	dec := envdetect.Decide(r.cfg.Targets)

	// auto iface
	if r.cfg.Interface == "" {
		ifc, err := envdetect.DetectDefaultInterface()
		if err == nil {
			r.cfg.Interface = ifc
		}
	}

	// wait
	wait := r.cfg.WaitSeconds
	if wait <= 0 {
		wait = dec.WaitSeconds
	}

	resolvedPorts := resolvePorts(r.cfg.Ports, dec.PreferredEngine)

	run := &model.ScanRun{
		ID:           newUUID(),
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

	if dec.PreferredEngine == "masscan" {
		r.hub.Publish(Progress{Percent: 30, Message: "Running masscan"})
		mr, err := masscan.RunCtx(ctx, &engineCfg)
		if err != nil && ctx.Err() == nil {
			logger.Errorf("masscan error: %v", err)
		}
		found = mr

		if len(found) == 0 {
			r.hub.Publish(Progress{Percent: 45, Message: "Masscan returned 0, fallback to nmap"})
			engineUsed = "mixed"

			nr, err := nmap.RunCtx(ctx, &engineCfg)
			if err != nil {
				return nil, err
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
			return nil, err
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

	r.hub.Publish(Progress{Percent: 70, Message: "Analyzing banners & storing results"})

	totalFound := 0
	newFound := 0
	seen := map[string]struct{}{}
	lastTick := time.Now()

	for i, fr := range found {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
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

		// ✅ Пишем результаты в Postgres (если подключен)
		if r.pg != nil {
			// нормализация IP для inet (убираем скобки и мусор)
			ip := strings.TrimSpace(fr.IP)
			ip = strings.TrimPrefix(ip, "(")
			ip = strings.TrimSuffix(ip, ")")

			hostID, err := r.pg.UpsertHost(ip)
			if err != nil {
				logger.Errorf("upsert host error: %v (ip=%q)", err, ip)
				continue
			}

			isNew, err := r.pg.UpsertPort(
				hostID,
				int(fr.Port),
				strings.ToLower(fr.Proto),
				svc,
				bnr,
			)

			if err != nil {
				logger.Errorf("upsert port error: %v", err)
				continue
			}

			if isNew {
				newFound++
				_ = r.pg.AddEvent("new_port", map[string]any{
					"ip":      fr.IP,
					"port":    int(fr.Port),
					"service": svc,
				})
			}
		}

		// прогресс
		if time.Since(lastTick) > 700*time.Millisecond && len(found) > 0 {
			lastTick = time.Now()
			p := 70 + int(float64(i+1)/float64(len(found))*25.0)
			if p > 95 {
				p = 95
			}
			r.hub.Publish(Progress{Percent: p, Message: fmt.Sprintf("Processed %d/%d", i+1, len(found))})
		}
	}

	run.FinishedAt = time.Now().UTC()
	run.Found = totalFound
	run.NewFound = newFound
	run.Engine = engineUsed

	// ✅ scan-run в Postgres
	if r.pg != nil {
		if err := r.pg.AddScanRun(run, r.cfg.Targets); err != nil {
			logger.Errorf("add scan run failed: %v", err)
		}
	} else if r.store != nil {
		_ = r.store.AddScanRun(run)
	}

	r.hub.Publish(Progress{Percent: 98, Message: "Finalizing"})
	return run, nil
}
