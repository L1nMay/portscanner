package model

import (
	"fmt"
	"time"
)

type ScanResult struct {
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	Proto     string    `json:"proto"`
	Banner    string    `json:"banner,omitempty"`
	Service   string    `json:"service,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

func (r *ScanResult) Key() string {
	return r.IP + ":" + fmt.Sprintf("%d", r.Port)
}
