package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"shadow/internal/store"
)

//go:embed index.html app.js style.css
var assets embed.FS

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type Server struct {
	http  *http.Server
	ln    net.Listener
	token string
}

func Start(st *store.Store) (*Server, string, error) {
	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, "", err
	}
	token := hex.EncodeToString(secret[:])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	files, err := fs.Sub(assets, ".")
	if err != nil {
		ln.Close()
		return nil, "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if provided := r.URL.Query().Get("token"); provided != "" {
			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				http.Error(w, "invalid token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "shadow_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.ServeFileFS(w, r, files, "index.html")
	})
	mux.Handle("GET /app.js", http.FileServerFS(files))
	mux.Handle("GET /style.css", http.FileServerFS(files))
	mux.HandleFunc("GET /api/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		runs, err := st.Runs(r.Context(), 50)
		writeJSON(w, runs, err)
	})
	mux.HandleFunc("GET /api/v1/runs/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !runIDPattern.MatchString(id) {
			http.Error(w, "invalid run id", http.StatusBadRequest)
			return
		}
		events, err := st.Events(r.Context(), id)
		writeJSON(w, events, err)
	})
	mux.HandleFunc("GET /api/v1/runs/{id}/findings", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !runIDPattern.MatchString(id) {
			http.Error(w, "invalid run id", http.StatusBadRequest)
			return
		}
		findings, err := st.Findings(r.Context(), id)
		writeJSON(w, findings, err)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		if r.URL.Path != "/" || r.URL.Query().Get("token") == "" {
			cookie, err := r.Cookie("shadow_session")
			if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
	srv := &Server{ln: ln, token: token}
	srv.http = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.http.Serve(ln) }()
	return srv, fmt.Sprintf("http://%s/?token=%s", ln.Addr().String(), token), nil
}

func (s *Server) Close() error { return s.http.Close() }

func writeJSON(w http.ResponseWriter, value any, err error) {
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if value == nil {
		value = []any{}
	}
	_ = json.NewEncoder(w).Encode(value)
}

func IsLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}
