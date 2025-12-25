package scan

import (
	"context"
	"sync"
)

type cancelState struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (r *Runner) setCancel(fn context.CancelFunc) {
	r.muCancel.mu.Lock()
	defer r.muCancel.mu.Unlock()
	r.muCancel.cancel = fn
}

func (r *Runner) clearCancel() {
	r.muCancel.mu.Lock()
	defer r.muCancel.mu.Unlock()
	r.muCancel.cancel = nil
}

func (r *Runner) IsRunning() bool {
	r.muCancel.mu.Lock()
	defer r.muCancel.mu.Unlock()
	return r.muCancel.cancel != nil
}

/*
CancelRunning — безопасно останавливает текущий скан
*/
func (r *Runner) CancelRunning() bool {
	r.muCancel.mu.Lock()
	defer r.muCancel.mu.Unlock()

	if r.muCancel.cancel == nil {
		return false
	}

	r.muCancel.cancel()
	r.muCancel.cancel = nil

	if r.hub != nil {
		r.hub.Publish(Progress{
			Percent: 100,
			Message: "Scan cancelled by user",
		})
	}

	return true
}
