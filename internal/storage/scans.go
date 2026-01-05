package storage

import (
	"time"
)

type ScanRun struct {
	ID           int64     `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Engine       string    `json:"engine"`
	TargetsCount int       `json:"targets_count"`
	Found        int       `json:"found"`
	NewFound     int       `json:"new_found"`
	PortsSpec    string    `json:"ports_spec"`
	Notes        string    `json:"notes"`
}

func (p *Postgres) ListScanRuns(limit int) ([]ScanRun, error) {
	rows, err := p.db.Query(`
		SELECT
			id,
			started_at,
			finished_at,
			engine,
			targets_count,
			found,
			new_found,
			ports_spec,
			notes
		FROM scans
		ORDER BY started_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ScanRun{}

	for rows.Next() {
		var r ScanRun
		if err := rows.Scan(
			&r.ID,
			&r.StartedAt,
			&r.FinishedAt,
			&r.Engine,
			&r.TargetsCount,
			&r.Found,
			&r.NewFound,
			&r.PortsSpec,
			&r.Notes,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	return out, rows.Err()
}
