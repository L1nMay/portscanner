package webui

import (
	"embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/envdetect"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/scan"
	"github.com/L1nMay/portscanner/internal/storage"
)

//go:embed assets/*
var assetsFS embed.FS

type Server struct {
	store  *storage.Storage
	runner *scan.Runner
	cfg    *config.Config
}

type ScanRequest struct {
	Targets []string `json:"targets"`
	Ports   string   `json:"ports"`
}

func NewServer(cfg *config.Config, store *storage.Storage, runner *scan.Runner) *Server {
	return &Server{
		cfg:    cfg,
		store:  store,
		runner: runner,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ---------- Static ----------
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := assetsFS.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, "index not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		b, err := assetsFS.ReadFile("assets/app.js")
		if err != nil {
			http.Error(w, "app.js not found", 500)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		b, err := assetsFS.ReadFile("assets/style.css")
		if err != nil {
			http.Error(w, "style.css not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	})

	// ---------- API ----------
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"ok": true,
			"ts": time.Now().UTC(),
		})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		st, err := s.store.GetStats()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, st)
	})

	mux.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		res, err := s.store.ListResults()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, res)
	})

	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		runs, err := s.store.ListScanRuns(50)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, runs)
	})

	// ---------- Default scan (ASYNC) ----------
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}

		if s.runner.IsRunning() {
			http.Error(w, "scan already running", http.StatusConflict) // 409
			return
		}

		cfg := *s.cfg
		cfg.UserDefined = false

		s.runner.RunAsync(&cfg)
		writeJSON(w, 200, map[string]any{"status": "started"})
	})

	// ---------- Network info ----------
	mux.HandleFunc("/api/netinfo", func(w http.ResponseWriter, r *http.Request) {
		ni, err := envdetect.DetectNetInfo()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, ni)
	})

	mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
		nets, err := envdetect.DetectLocalNetworks()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, nets)
	})

	// ---------- Custom scan (ASYNC) ----------
	mux.HandleFunc("/api/scan/custom", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}

		if s.runner.IsRunning() {
			http.Error(w, "scan already running", http.StatusConflict) // 409
			return
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		cfg := *s.cfg
		cfg.Targets = req.Targets
		cfg.Ports = req.Ports
		cfg.UserDefined = true

		if err := scan.ValidateTargets(cfg.Targets); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}

		s.runner.RunAsync(&cfg)
		writeJSON(w, 200, map[string]any{"status": "started"})
	})

	// ---------- Scan progress (SSE) ----------
	mux.HandleFunc("/api/scan/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", 500)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ch := s.runner.HubSubscribe()
		defer s.runner.HubUnsubscribe(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case b := <-ch:
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(b)
				_, _ = w.Write([]byte("\n\n"))
				flusher.Flush()
			}
		}
	})

	// ---------- Cancel scan ----------
	mux.HandleFunc("/api/scan/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		ok := s.runner.CancelRunning()
		writeJSON(w, 200, map[string]any{"cancelled": ok})
	})

	return withCORS(withLogging(mux))
}

// ---------- Middleware ----------
func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("webui %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
