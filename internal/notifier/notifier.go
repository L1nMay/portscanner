package notifier

import "github.com/L1nMay/portscanner/internal/model"

type Notifier interface {
	NotifyNewOpenPorts(results []*model.ScanResult) error
}
