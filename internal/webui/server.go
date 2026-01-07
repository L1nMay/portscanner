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
	mux.HandleFunc("/", serveAsset("assets/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("/app.js", serveAsset("assets/app.js", "application/javascript; charset=utf-8"))
	mux.HandleFunc("/style.css", serveAsset("assets/style.css", "text/css; charset=utf-8"))

	// ---------- Health ----------
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"ok": true,
			"ts": time.Now().UTC(),
		})
	})

	// ---------- SSE ----------
	mux.HandleFunc("/api/scan/stream", s.handleStream)

	// ---------- API ----------
	api := http.NewServeMux()
	api.HandleFunc("/api/stats", s.handleStats)
	api.HandleFunc("/api/results", s.handleResults)
	api.HandleFunc("/api/scans", s.handleScans)
	api.HandleFunc("/api/netinfo", s.handleNetinfo)
	api.HandleFunc("/api/scan", s.handleScan)
	api.HandleFunc("/api/scan/custom", s.handleCustomScan)
	api.HandleFunc("/api/scan/cancel", s.handleCancel)
	api.HandleFunc("/api/scan/plan", s.handlePlan)

	mux.Handle("/api/", withAuth(s.cfg, api))

	return withCORS(withLogging(mux))
}

/* ========================= HANDLERS ========================= */

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.pg.GetStats()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleResults(w http.ResponseWriter, _ *http.Request) {
	res, err := s.pg.ListResults()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleScans(w http.ResponseWriter, _ *http.Request) {
	runs, err := s.pg.ListScanRuns(50)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	type scanRow struct {
		ID        string `json:"id"`
		StartedAt string `json:"started_at"`
		Engine    string `json:"engine"`
		Targets   string `json:"targets"`
		Ports     string `json:"ports"`
		Found     int    `json:"found"`
		New       int    `json:"new"`
		Status    string `json:"status"`
	}

	out := make([]scanRow, 0, len(runs))
	for _, r := range runs {
		out = append(out, scanRow{
			ID:        r.ID,
			StartedAt: r.StartedAt.Format(time.RFC3339),
			Engine:    r.Engine,
			Targets:   r.Targets,
			Ports:     r.Ports,
			Found:     r.Found,
			New:       r.NewFound,
			Status:    r.Status,
		})
	}

	writeJSON(w, 200, out)
}

func (s *Server) handleNetinfo(w http.ResponseWriter, _ *http.Request) {
	ni, err := envdetect.DetectNetInfo()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, ni)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	cfg := *s.cfg
	cfg.UserDefined = false
	s.runner.RunAsync(&cfg)
	writeJSON(w, 200, map[string]any{"status": "started"})
}

func (s *Server) handleCustomScan(w http.ResponseWriter, r *http.Request) {
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
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	ok := s.runner.CancelRunning()
	writeJSON(w, 200, map[string]any{"cancelled": ok})
}

func (s *Server) handlePlan(w http.ResponseWriter, _ *http.Request) {
	plan, err := s.runner.Plan(s.cfg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, 200, plan)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

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
}

/* ========================= HELPERS ========================= */

func serveAsset(path, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := assetsFS.ReadFile(path)
		if err != nil {
			http.Error(w, "asset not found", 500)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(b)
	}
}

func withAuth(cfg *config.Config, next http.Handler) http.Handler {
	token := strings.TrimSpace(cfg.WebUI.AuthToken)
	if token == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if h == "" {
			http.Error(w, "missing Authorization header", 401)
			return
		}
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			h = strings.TrimSpace(h[7:])
		}
		if h != token {
			http.Error(w, "invalid token", 403)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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
