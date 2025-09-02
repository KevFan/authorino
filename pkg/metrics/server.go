package metrics

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SwappableHTTPHandler is an http.Handler that can be atomically swapped.
type SwappableHTTPHandler struct{ h atomic.Value }

// NewSwappableHTTPHandler creates a new SwappableHTTPHandler.
func NewSwappableHTTPHandler() *SwappableHTTPHandler {
	h := &SwappableHTTPHandler{}
	// Start with a handler for the default registry, it will be swapped later.
	h.h.Store(promhttp.Handler())
	return h
}

func (s *SwappableHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := s.h.Load().(http.Handler)
	h.ServeHTTP(w, r)
}

// Swap replaces the existing handler with a new one for a given registry.
func (s *SwappableHTTPHandler) Swap(registry *prometheus.Registry) {
	s.h.Store(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
}

// Handler is the global instance of the swappable handler for metrics.
var Handler = NewSwappableHTTPHandler()
