package webui

import (
	"embed"
	"encoding/json"
	"net/http"
	"strings"
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
    pg     *storage.Postgres
    runner *scan.Runner
    cfg    *config.Config
}

type ScanRequest struct {
	Targets []string `json:"targets"`
	Ports   string   `json:"ports"`
}

func NewServer(cfg *config.Config, pg *storage.Postgres, runner *scan.Runner) *Server {
    return &Server{
        cfg:    cfg,
        pg:     pg,
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

	// ---------- Health (no auth) ----------
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "ts": time.Now().UTC()})
	})

	// ---------- SSE (ВАЖНО: БЕЗ AUTH, напрямую на mux) ----------
	mux.HandleFunc("/api/scan/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", 500)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// полезно, если когда-то будет прокси
		w.Header().Set("X-Accel-Buffering", "no")

		// сразу пошлём "комментарий", чтобы браузер точно открыл соединение
		_, _ = w.Write([]byte(": ok\n\n"))
		flusher.Flush()

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

	// ---------- API (auth) ----------
	api := http.NewServeMux()

	api.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		st, err := s.pg.GetStats()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, st)
	})

	api.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		res, err := s.pg.ListResults()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, res)
	})

	api.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		runs, err := s.pg.ListScanRuns(50)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, runs)
	})

	api.HandleFunc("/api/netinfo", func(w http.ResponseWriter, r *http.Request) {
		ni, err := envdetect.DetectNetInfo()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, ni)
	})

	// общий scan — async
	api.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		cfg := *s.cfg
		cfg.UserDefined = false
		s.runner.RunAsync(&cfg)
		writeJSON(w, 200, map[string]any{"status": "started"})
	})

	// custom scan — async
	api.HandleFunc("/api/scan/custom", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
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

	api.HandleFunc("/api/scan/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		ok := s.runner.CancelRunning()
		writeJSON(w, 200, map[string]any{"cancelled": ok})
	})

	api.HandleFunc("/api/scan/plan", func(w http.ResponseWriter, r *http.Request) {
		plan, err := s.runner.Plan(s.cfg)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, 200, plan)
	})

	// ВЕСЬ /api/ (кроме /api/scan/stream и /api/health) — через auth
	mux.Handle("/api/", withAuth(s.cfg, api))

	return withCORS(withLogging(mux))
}

// ---------- AUTH ----------
func withAuth(cfg *config.Config, next http.Handler) http.Handler {
	if strings.TrimSpace(cfg.WebUI.AuthToken) == "" {
		return next
	}

	want := strings.TrimSpace(cfg.WebUI.AuthToken)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if h == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			h = strings.TrimSpace(h[7:])
		}
		if h != want {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
