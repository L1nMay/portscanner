package scan

// HubSubscribe позволяет WebUI подписаться на прогресс сканирования (SSE)
func (r *Runner) HubSubscribe() chan []byte {
	if r.hub == nil {
		return nil
	}
	return r.hub.Subscribe()
}

// HubUnsubscribe отписывает клиента от SSE
func (r *Runner) HubUnsubscribe(ch chan []byte) {
	if r.hub == nil || ch == nil {
		return
	}
	r.hub.Unsubscribe(ch)
}
