package scan

import (
	"encoding/json"
	"sync"
)

type Progress struct {
	Percent int    `json:"percent"`
	Message string `json:"message"`
}

type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan []byte]struct{})}
}

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) Publish(p Progress) {
	b, _ := json.Marshal(p)
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
	h.mu.Unlock()
}
