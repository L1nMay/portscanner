package storage

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/L1nMay/portscanner/internal/model"
	"go.etcd.io/bbolt"
)

const (
	bucketPorts = "ports"
	bucketScans = "scans"
)

type Storage struct {
	db *bbolt.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists([]byte(bucketPorts)); e != nil {
			return e
		}
		if _, e := tx.CreateBucketIfNotExists([]byte(bucketScans)); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Storage{db: db}, nil
}

func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Storage) Exists(key string) (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPorts))
		if b == nil {
			return errors.New("bucket not found")
		}
		exists = b.Get([]byte(key)) != nil
		return nil
	})
	return exists, err
}

func (s *Storage) GetResult(key string) (*model.ScanResult, bool, error) {
	var res *model.ScanResult
	var ok bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPorts))
		if b == nil {
			return errors.New("bucket not found")
		}
		v := b.Get([]byte(key))
		if v == nil {
			ok = false
			return nil
		}
		var r model.ScanResult
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		res = &r
		ok = true
		return nil
	})
	return res, ok, err
}

// UpsertResult: если уже был — обновляем LastSeen и поля; если новый — ставим FirstSeen/LastSeen
func (s *Storage) UpsertResult(r *model.ScanResult) (isNew bool, err error) {
	key := r.Key()
	now := time.Now().UTC()

	returnedNew := false

	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPorts))
		if b == nil {
			return errors.New("bucket not found")
		}

		v := b.Get([]byte(key))
		if v == nil {
			returnedNew = true
			if r.FirstSeen.IsZero() {
				r.FirstSeen = now
			}
			r.LastSeen = now
		} else {
			var old model.ScanResult
			if err := json.Unmarshal(v, &old); err != nil {
				return err
			}
			// сохраняем первый раз
			r.FirstSeen = old.FirstSeen
			r.LastSeen = now
			// если баннер пустой сейчас, но был раньше — оставим старый
			if r.Banner == "" {
				r.Banner = old.Banner
			}
			if r.Service == "" {
				r.Service = old.Service
			}
		}

		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})

	return returnedNew, err
}

func (s *Storage) ListResults() ([]model.ScanResult, error) {
	out := make([]model.ScanResult, 0, 256)

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPorts))
		if b == nil {
			return errors.New("bucket not found")
		}
		return b.ForEach(func(k, v []byte) error {
			var r model.ScanResult
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// сортировка: сначала свежие
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	return out, nil
}

type Stats struct {
	TotalFindings int `json:"total_findings"`
	UniqueHosts   int `json:"unique_hosts"`
}

func (s *Storage) GetStats() (Stats, error) {
	results, err := s.ListResults()
	if err != nil {
		return Stats{}, err
	}
	hosts := map[string]struct{}{}
	for _, r := range results {
		hosts[r.IP] = struct{}{}
	}
	return Stats{
		TotalFindings: len(results),
		UniqueHosts:   len(hosts),
	}, nil
}

func (s *Storage) AddScanRun(run *model.ScanRun) error {
	data, err := json.Marshal(run)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketScans))
		if b == nil {
			return errors.New("bucket not found")
		}
		return b.Put([]byte(run.ID), data)
	})
}

func (s *Storage) ListScanRuns(limit int) ([]model.ScanRun, error) {
	out := []model.ScanRun{}

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketScans))
		if b == nil {
			return errors.New("bucket not found")
		}
		return b.ForEach(func(k, v []byte) error {
			var r model.ScanRun
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
