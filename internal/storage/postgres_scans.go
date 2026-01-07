package storage

import "github.com/L1nMay/portscanner/internal/model"

func (p *Postgres) AddScanRun(run *model.ScanRun, targets []string) error {
	targetsStr := ""
	if len(targets) > 0 {
		targetsStr = targets[0]
		if len(targets) > 1 {
			targetsStr = targetsStr + " (+" + string(len(targets)-1) + ")"
		}
	}

	_, err := p.db.Exec(`
		INSERT INTO scans (
			id,
			started_at,
			finished_at,
			engine,
			targets,
			ports,
			found,
			new_found,
			status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		run.ID,
		run.StartedAt,
		run.FinishedAt,
		run.Engine,
		targetsStr,
		run.PortsSpec,
		run.Found,
		run.NewFound,
		"finished",
	)

	return err
}
