package storage

import (
	"encoding/json"
	"errors"

	"github.com/L1nMay/portscanner/internal/model"
	"go.etcd.io/bbolt"
)

const bucketName = "ports"

type Storage struct {
	db *bbolt.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
	if err != nil {
		db.Close()
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
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		v := b.Get([]byte(key))
		exists = v != nil
		return nil
	})
	return exists, err
}

func (s *Storage) PutResult(res *model.ScanResult) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		return b.Put([]byte(res.Key()), data)
	})
}
