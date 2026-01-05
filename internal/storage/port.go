package storage

func (p *Postgres) UpsertPort(
	hostID int64,
	port int,
	proto string,
	service string,
	banner string,
) (bool, error) {

	var isNew bool
	err := p.db.QueryRow(`
		INSERT INTO ports (host_id, port, proto, service, banner, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,now(),now())
		ON CONFLICT (host_id, port, proto)
		DO UPDATE SET
			last_seen = now(),
			service = COALESCE(EXCLUDED.service, ports.service),
			banner  = COALESCE(EXCLUDED.banner, ports.banner)
		RETURNING (xmax = 0)
	`, hostID, port, proto, service, banner).Scan(&isNew)

	return isNew, err
}
