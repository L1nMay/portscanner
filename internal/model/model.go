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
	LastSeen  time.Time `json:"last_seen"`
}

func (r *ScanResult) Key() string {
	return r.IP + ":" + fmt.Sprintf("%d", r.Port)
}

type ScanRun struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	TargetsCount int       `json:"targets_count"`
	PortsSpec    string    `json:"ports_spec"`
	Engine       string    `json:"engine"` // masscan|nmap|mixed
	Found        int       `json:"found"`
	NewFound     int       `json:"new_found"`
	Notes        string    `json:"notes,omitempty"`
}
