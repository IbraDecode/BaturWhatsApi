package apiserver

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/ibradecode/baturwhatsapi/statemachine"
)

// hMetrics renders engine + Go runtime metrics in Prometheus text format
// (version 0.0.4). This is the observability gate: every supervision,
// session and transport signal is exposed so external Prometheus can scrape
// the 24/7 runtime without log scraping.
func (s *Server) hMetrics(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	health := s.Batur.Health()
	ids := make([]string, 0, len(health))
	for id := range health {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	sb.WriteString("# HELP batur_session_state Session connection state (1) per enumerated state.\n")
	sb.WriteString("# TYPE batur_session_state gauge\n")
	states := []statemachine.State{
		statemachine.Stopped, statemachine.Starting, statemachine.Connecting,
		statemachine.Authenticating, statemachine.Syncing, statemachine.Online,
		statemachine.Degraded, statemachine.Reconnecting, statemachine.Error,
	}
	for _, id := range ids {
		h := health[id]
		for _, st := range states {
			v := 0
			if h.State == string(st) {
				v = 1
			}
			fmt.Fprintf(&sb, "batur_session_state{session=%q,state=%q} %d\n", id, string(st), v)
		}
	}

	sb.WriteString("# HELP batur_session_retries Total reconnect attempts per session.\n")
	sb.WriteString("# TYPE batur_session_retries counter\n")
	for _, id := range ids {
		fmt.Fprintf(&sb, "batur_session_retries{session=%q} %d\n", id, health[id].Retries)
	}

	sb.WriteString("# HELP batur_sessions Total registered sessions.\n")
	sb.WriteString("# TYPE batur_sessions gauge\n")
	fmt.Fprintf(&sb, "batur_sessions %d\n", len(ids))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sb.WriteString("# HELP batur_online_sessions Sessions currently ONLINE.\n")
	sb.WriteString("# TYPE batur_online_sessions gauge\n")
	online := 0
	for _, id := range ids {
		if health[id].State == string(statemachine.Online) {
			online++
		}
	}
	fmt.Fprintf(&sb, "batur_online_sessions %d\n", online)

	sb.WriteString("# HELP batur_goroutines Active goroutines.\n# TYPE batur_goroutines gauge\n")
	fmt.Fprintf(&sb, "batur_goroutines %d\n", runtime.NumGoroutine())
	sb.WriteString("# HELP batur_heap_alloc_bytes Heap bytes allocated and live.\n# TYPE batur_heap_alloc_bytes gauge\n")
	fmt.Fprintf(&sb, "batur_heap_alloc_bytes %d\n", ms.HeapAlloc)
	sb.WriteString("# HELP batur_sys_bytes Total bytes obtained from system.\n# TYPE batur_sys_bytes gauge\n")
	fmt.Fprintf(&sb, "batur_sys_bytes %d\n", ms.Sys)
	sb.WriteString("# HELP batur_gc_pause_total_ns Sum of GC pause nanoseconds.\n# TYPE batur_gc_pause_total_ns counter\n")
	fmt.Fprintf(&sb, "batur_gc_pause_total_ns %d\n", ms.PauseTotalNs)

	sb.WriteString("# HELP batur_ws_connections Live WebSocket event subscribers.\n")
	sb.WriteString("# TYPE batur_ws_connections gauge\n")
	fmt.Fprintf(&sb, "batur_ws_connections %d\n", wsConnections.Load())

	// event bus stats
	if b := s.Batur.Bus(); b != nil {
		bs := b.Stats()
		sb.WriteString("# HELP batur_events_published_total Total events published on the bus.\n# TYPE batur_events_published_total counter\n")
		fmt.Fprintf(&sb, "batur_events_published_total %d\n", bs.Published)
		sb.WriteString("# HELP batur_events_dropped_total Events dropped by policy.\n# TYPE batur_events_dropped_total counter\n")
		fmt.Fprintf(&sb, "batur_events_dropped_total %d\n", bs.Dropped)
		sb.WriteString("# HELP batur_event_subscribers Current subscriber count.\n# TYPE batur_event_subscribers gauge\n")
		fmt.Fprintf(&sb, "batur_event_subscribers %d\n", bs.Subscribers)
	}
	_, _ = w.Write([]byte(sb.String()))
}

var _ = strconv.Itoa
