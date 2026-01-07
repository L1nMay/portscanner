package storage

import "time"

type ScanRun struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Engine     string    `json:"engine"`
	Targets    string    `json:"targets"`
	Ports      string    `json:"ports"`
	Found      int       `json:"found"`
	NewFound   int       `json:"new_found"`
	Status     string    `json:"status"`
}

func (p *Postgres) ListScanRuns(limit int) ([]ScanRun, error) {
	rows, err := p.db.Query(`
        SELECT
            id,
            started_at,
            finished_at,
            engine,
            targets,
            ports,
            found,
            new_found,
            status
        FROM scans
        ORDER BY started_at DESC
        LIMIT $1
    `, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ScanRun, 0)
	for rows.Next() {
		var r ScanRun
		if err := rows.Scan(
			&r.ID,
			&r.StartedAt,
			&r.FinishedAt,
			&r.Engine,
			&r.Targets,
			&r.Ports,
			&r.Found,
			&r.NewFound,
			&r.Status,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
