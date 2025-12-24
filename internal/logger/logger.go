package logger

import (
	"log"
	"os"
)

var (
	stdLogger *log.Logger
)

func init() {
	stdLogger = log.New(os.Stdout, "[portscanner] ", log.LstdFlags|log.Lshortfile)
}

func Infof(format string, v ...interface{}) {
	stdLogger.Printf("[INFO] "+format, v...)
}

func Errorf(format string, v ...interface{}) {
	stdLogger.Printf("[ERROR] "+format, v...)
}

func Fatalf(format string, v ...interface{}) {
	stdLogger.Fatalf("[FATAL] "+format, v...)
}
