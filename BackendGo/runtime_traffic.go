package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var trafficLatencyBounds = []float64{50, 100, 200, 400, 800, 1200, 2000, 3000, 5000, 8000, 12000}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Status() int {
	return r.statusCode
}

type TrafficRouteStats struct {
	Requests         int64            `json:"requests"`
	OK               int64            `json:"ok"`
	Errors           int64            `json:"errors"`
	TotalLatencyMs   float64          `json:"total_latency_ms"`
	MaxLatencyMs     float64          `json:"max_latency_ms"`
	StatusBuckets    map[string]int64 `json:"status_buckets,omitempty"`
	ErrorBuckets     map[string]int64 `json:"error_buckets,omitempty"`
	LatencyHistogram map[string]int64 `json:"latency_histogram,omitempty"`
}

type TrafficAggregate struct {
	Total  *TrafficRouteStats            `json:"total"`
	Routes map[string]*TrafficRouteStats `json:"routes"`
}

type TrafficDailySnapshot struct {
	Schema    int               `json:"schema"`
	Day       string            `json:"day"`
	UpdatedAt time.Time         `json:"updated_at"`
	Aggregate *TrafficAggregate `json:"aggregate"`
}

type TrafficRouteSummary struct {
	Route            string           `json:"route"`
	Requests         int64            `json:"requests"`
	OK               int64            `json:"ok"`
	Errors           int64            `json:"errors"`
	ErrorRatePercent float64          `json:"error_rate_percent"`
	AvgLatencyMs     float64          `json:"avg_latency_ms"`
	P95LatencyMs     float64          `json:"p95_latency_ms"`
	MaxLatencyMs     float64          `json:"max_latency_ms"`
	StatusBuckets    map[string]int64 `json:"status_buckets,omitempty"`
	ErrorBuckets     map[string]int64 `json:"error_buckets,omitempty"`
}

func NewRuntimeMonitor(cfg Config) *RuntimeMonitor {
	now := time.Now().UTC()
	monitor := &RuntimeMonitor{
		StartTime:     now,
		Enabled:       cfg.WorkerMetricsEnabled,
		MetricsDir:    strings.TrimSpace(cfg.RuntimeMetricsDir),
		RetentionDays: maxInt(cfg.RuntimeMetricsRetentionDays, 1),
		FlushSeconds:  maxInt(cfg.RuntimeMetricsFlushSeconds, 5),
		OnlineWindow:  time.Duration(maxInt(cfg.HeartbeatIntervalSeconds+cfg.HeartbeatJitterSeconds+30, 60)) * time.Second,
		DayKey:        now.Format("2006-01-02"),
		TodayBaseline: newTrafficAggregate(),
		TodaySession:  newTrafficAggregate(),
		Sessions:      map[string]*RuntimeSessionInfo{},
	}
	monitor.initializePersistence()
	return monitor
}

func newTrafficAggregate() *TrafficAggregate {
	return &TrafficAggregate{
		Total:  newTrafficRouteStats(),
		Routes: map[string]*TrafficRouteStats{},
	}
}

func newTrafficRouteStats() *TrafficRouteStats {
	return &TrafficRouteStats{
		StatusBuckets:    map[string]int64{},
		ErrorBuckets:     map[string]int64{},
		LatencyHistogram: map[string]int64{},
	}
}

func cloneTrafficAggregate(source *TrafficAggregate) *TrafficAggregate {
	if source == nil {
		return newTrafficAggregate()
	}
	cloned := &TrafficAggregate{
		Total:  cloneTrafficRouteStats(source.Total),
		Routes: map[string]*TrafficRouteStats{},
	}
	for route, stats := range source.Routes {
		cloned.Routes[route] = cloneTrafficRouteStats(stats)
	}
	return cloned
}

func cloneTrafficRouteStats(source *TrafficRouteStats) *TrafficRouteStats {
	if source == nil {
		return newTrafficRouteStats()
	}
	cloned := &TrafficRouteStats{
		Requests:         source.Requests,
		OK:               source.OK,
		Errors:           source.Errors,
		TotalLatencyMs:   source.TotalLatencyMs,
		MaxLatencyMs:     source.MaxLatencyMs,
		StatusBuckets:    map[string]int64{},
		ErrorBuckets:     map[string]int64{},
		LatencyHistogram: map[string]int64{},
	}
	for key, value := range source.StatusBuckets {
		cloned.StatusBuckets[key] = value
	}
	for key, value := range source.ErrorBuckets {
		cloned.ErrorBuckets[key] = value
	}
	for key, value := range source.LatencyHistogram {
		cloned.LatencyHistogram[key] = value
	}
	return cloned
}

func mergeTrafficAggregate(dst *TrafficAggregate, src *TrafficAggregate) {
	if dst == nil || src == nil {
		return
	}
	mergeTrafficRouteStats(dst.Total, src.Total)
	for route, stats := range src.Routes {
		target := dst.Routes[route]
		if target == nil {
			target = newTrafficRouteStats()
			dst.Routes[route] = target
		}
		mergeTrafficRouteStats(target, stats)
	}
}

func mergeTrafficRouteStats(dst *TrafficRouteStats, src *TrafficRouteStats) {
	if dst == nil || src == nil {
		return
	}
	dst.Requests += src.Requests
	dst.OK += src.OK
	dst.Errors += src.Errors
	dst.TotalLatencyMs += src.TotalLatencyMs
	if src.MaxLatencyMs > dst.MaxLatencyMs {
		dst.MaxLatencyMs = src.MaxLatencyMs
	}
	for key, value := range src.StatusBuckets {
		dst.StatusBuckets[key] += value
	}
	for key, value := range src.ErrorBuckets {
		dst.ErrorBuckets[key] += value
	}
	for key, value := range src.LatencyHistogram {
		dst.LatencyHistogram[key] += value
	}
}

func (m *RuntimeMonitor) initializePersistence() {
	if !m.Enabled || strings.TrimSpace(m.MetricsDir) == "" {
		return
	}
	_ = os.MkdirAll(m.MetricsDir, 0o755)
	m.cleanupOldSnapshots()
	if baseline, err := loadTrafficAggregateFromFile(m.snapshotPathForDay(m.DayKey)); err == nil && baseline != nil {
		m.TodayBaseline = baseline
	}
	go m.backgroundFlushLoop()
}

func (m *RuntimeMonitor) backgroundFlushLoop() {
	ticker := time.NewTicker(time.Duration(m.FlushSeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.flushToDisk()
	}
}

func (m *RuntimeMonitor) snapshotPathForDay(day string) string {
	return filepath.Join(m.MetricsDir, "traffic-"+day+".json")
}

func (m *RuntimeMonitor) rolloverIfNeededLocked(now time.Time) {
	if !m.Enabled {
		return
	}
	currentDay := now.UTC().Format("2006-01-02")
	if currentDay == m.DayKey {
		return
	}
	previousPath := m.snapshotPathForDay(m.DayKey)
	_ = writeTrafficAggregateToFile(previousPath, m.buildTodayAggregateLocked(), m.DayKey)
	m.cleanupOldSnapshots()
	m.DayKey = currentDay
	m.TodayBaseline = newTrafficAggregate()
	if baseline, err := loadTrafficAggregateFromFile(m.snapshotPathForDay(currentDay)); err == nil && baseline != nil {
		m.TodayBaseline = baseline
	}
	m.TodaySession = newTrafficAggregate()
}

func (m *RuntimeMonitor) recordRequestLocked(method string, route string, status int, elapsed time.Duration) {
	if !m.Enabled {
		return
	}
	routeKey := strings.TrimSpace(method + " " + route)
	if routeKey == "" {
		routeKey = strings.TrimSpace(method + " unknown")
	}
	latencyMs := float64(elapsed.Milliseconds())
	if latencyMs <= 0 {
		latencyMs = float64(elapsed) / float64(time.Millisecond)
	}
	updateTrafficRouteStats(m.TodaySession.Total, status, latencyMs)
	stats := m.TodaySession.Routes[routeKey]
	if stats == nil {
		stats = newTrafficRouteStats()
		m.TodaySession.Routes[routeKey] = stats
	}
	updateTrafficRouteStats(stats, status, latencyMs)
}

func updateTrafficRouteStats(stats *TrafficRouteStats, status int, latencyMs float64) {
	if stats == nil {
		return
	}
	stats.Requests++
	if status >= 200 && status < 400 {
		stats.OK++
	} else {
		stats.Errors++
	}
	stats.TotalLatencyMs += latencyMs
	if latencyMs > stats.MaxLatencyMs {
		stats.MaxLatencyMs = latencyMs
	}
	statusKey := strconv.Itoa(status)
	stats.StatusBuckets[statusKey]++
	if status >= 400 && status < 500 {
		stats.ErrorBuckets["http_4xx"]++
	} else if status >= 500 {
		stats.ErrorBuckets["http_5xx"]++
	}
	stats.LatencyHistogram[latencyBucketLabel(latencyMs)]++
}

func latencyBucketLabel(latencyMs float64) string {
	for _, bound := range trafficLatencyBounds {
		if latencyMs <= bound {
			return "<=" + strconv.Itoa(int(bound))
		}
	}
	return ">12000"
}

func (m *RuntimeMonitor) buildTodayAggregateLocked() *TrafficAggregate {
	combined := cloneTrafficAggregate(m.TodayBaseline)
	mergeTrafficAggregate(combined, m.TodaySession)
	return combined
}

func (m *RuntimeMonitor) flushToDisk() {
	if !m.Enabled || strings.TrimSpace(m.MetricsDir) == "" {
		return
	}
	m.mu.Lock()
	m.rolloverIfNeededLocked(time.Now().UTC())
	aggregate := m.buildTodayAggregateLocked()
	day := m.DayKey
	m.mu.Unlock()
	_ = os.MkdirAll(m.MetricsDir, 0o755)
	_ = writeTrafficAggregateToFile(m.snapshotPathForDay(day), aggregate, day)
	m.cleanupOldSnapshots()
}

func writeTrafficAggregateToFile(path string, aggregate *TrafficAggregate, day string) error {
	tmpPath := path + ".tmp"
	payload := TrafficDailySnapshot{
		Schema:    1,
		Day:       day,
		UpdatedAt: time.Now().UTC(),
		Aggregate: aggregate,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func loadTrafficAggregateFromFile(path string) (*TrafficAggregate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload TrafficDailySnapshot
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if payload.Aggregate == nil {
		return newTrafficAggregate(), nil
	}
	return payload.Aggregate, nil
}

func (m *RuntimeMonitor) cleanupOldSnapshots() {
	if strings.TrimSpace(m.MetricsDir) == "" {
		return
	}
	entries, err := os.ReadDir(m.MetricsDir)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -maxInt(m.RetentionDays, 1))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "traffic-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "traffic-"), ".json")
		parsed, err := time.Parse("2006-01-02", day)
		if err != nil {
			continue
		}
		if parsed.Before(cutoff) {
			_ = os.Remove(filepath.Join(m.MetricsDir, name))
		}
	}
}

func (m *RuntimeMonitor) cleanupSessionsLocked(now time.Time) {
	for sessionID, item := range m.Sessions {
		if item == nil {
			delete(m.Sessions, sessionID)
			continue
		}
		if !item.SessionExpiresAt.IsZero() && now.After(item.SessionExpiresAt) {
			delete(m.Sessions, sessionID)
			continue
		}
		if !item.LastSeenAt.IsZero() && now.Sub(item.LastSeenAt) > (m.OnlineWindow*2) {
			delete(m.Sessions, sessionID)
		}
	}
}

func (m *RuntimeMonitor) TouchSession(sessionID, accountUsername, machineID, route string, expiresAt time.Time) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupSessionsLocked(now)
	item := m.Sessions[sessionID]
	if item == nil {
		item = &RuntimeSessionInfo{
			SessionID: sessionID,
			StartedAt: now,
		}
		m.Sessions[sessionID] = item
	}
	if strings.TrimSpace(accountUsername) != "" {
		item.AccountUsername = strings.TrimSpace(accountUsername)
	}
	if strings.TrimSpace(machineID) != "" {
		item.MachineID = strings.TrimSpace(machineID)
	}
	item.LastSeenAt = now
	if route == "heartbeat" {
		item.LastHeartbeatAt = now
	}
	if !expiresAt.IsZero() {
		item.SessionExpiresAt = expiresAt.UTC()
	}
	if strings.TrimSpace(route) != "" {
		item.LastRoute = route
	}
}

func (m *RuntimeMonitor) ClearSession(sessionID string) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Sessions, sessionID)
}

func (m *RuntimeMonitor) buildConnectionReport(includeSessions bool) map[string]any {
	m.mu.Lock()
	now := time.Now().UTC()
	m.cleanupSessionsLocked(now)
	window := m.OnlineWindow
	activeSessions := make([]RuntimeSessionInfo, 0, len(m.Sessions))
	activeUsers := map[string]struct{}{}
	activeDevices := map[string]struct{}{}
	authoritativeUsers := map[string]struct{}{}
	authoritativeDevices := map[string]struct{}{}
	authoritativeSessions := int64(0)
	for _, item := range m.Sessions {
		if item == nil {
			continue
		}
		if !item.LastSeenAt.IsZero() && now.Sub(item.LastSeenAt) <= window {
			activeSessions = append(activeSessions, *item)
			if value := strings.TrimSpace(item.AccountUsername); value != "" {
				activeUsers[value] = struct{}{}
			}
			if value := strings.TrimSpace(item.MachineID); value != "" {
				activeDevices[value] = struct{}{}
			}
		}
		if !item.LastHeartbeatAt.IsZero() && now.Sub(item.LastHeartbeatAt) <= window {
			authoritativeSessions++
			if value := strings.TrimSpace(item.AccountUsername); value != "" {
				authoritativeUsers[value] = struct{}{}
			}
			if value := strings.TrimSpace(item.MachineID); value != "" {
				authoritativeDevices[value] = struct{}{}
			}
		}
	}
	m.mu.Unlock()

	sort.Slice(activeSessions, func(i, j int) bool {
		return activeSessions[i].LastSeenAt.After(activeSessions[j].LastSeenAt)
	})

	payload := map[string]any{
		"generated_at":                  now,
		"online_window_seconds":         int(window.Seconds()),
		"counting_rule":                 "authoritative_online_* counts unique accounts/devices with fresh heartbeat inside the online window",
		"active_runtime_sessions":       len(activeSessions),
		"active_runtime_users":          len(activeUsers),
		"active_runtime_devices":        len(activeDevices),
		"authoritative_online_sessions": authoritativeSessions,
		"authoritative_online_users":    len(authoritativeUsers),
		"authoritative_online_devices":  len(authoritativeDevices),
	}
	if includeSessions {
		payload["sessions"] = activeSessions
	}
	return payload
}

func (m *RuntimeMonitor) buildTrafficReport(windowDays int) map[string]any {
	m.mu.Lock()
	m.rolloverIfNeededLocked(time.Now().UTC())
	retentionDays := m.RetentionDays
	todayDay := m.DayKey
	todayAggregate := m.buildTodayAggregateLocked()
	inflight := m.ActiveRequests
	handled := m.Handled
	uptime := int(time.Since(m.StartTime).Seconds())
	metricsDir := m.MetricsDir
	m.mu.Unlock()

	if windowDays <= 0 || windowDays > retentionDays {
		windowDays = retentionDays
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -windowDays+1)
	combined := newTrafficAggregate()

	if strings.TrimSpace(metricsDir) != "" {
		entries, err := os.ReadDir(metricsDir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || !strings.HasPrefix(name, "traffic-") || !strings.HasSuffix(name, ".json") {
					continue
				}
				day := strings.TrimSuffix(strings.TrimPrefix(name, "traffic-"), ".json")
				if day == todayDay {
					continue
				}
				parsed, err := time.Parse("2006-01-02", day)
				if err != nil || parsed.Before(cutoff) {
					continue
				}
				if aggregate, err := loadTrafficAggregateFromFile(filepath.Join(metricsDir, name)); err == nil {
					mergeTrafficAggregate(combined, aggregate)
				}
			}
		}
	}
	mergeTrafficAggregate(combined, todayAggregate)

	routes := make([]TrafficRouteSummary, 0, len(combined.Routes))
	for route, stats := range combined.Routes {
		routes = append(routes, summarizeRoute(route, stats))
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Requests == routes[j].Requests {
			return routes[i].Route < routes[j].Route
		}
		return routes[i].Requests > routes[j].Requests
	})

	totalSummary := summarizeRoute("total", combined.Total)
	connectionSummary := m.buildConnectionReport(false)
	return map[string]any{
		"window_days":                 windowDays,
		"retention_days":              retentionDays,
		"generated_at":                time.Now().UTC(),
		"metrics_dir":                 metricsDir,
		"server_uptime_seconds":       uptime,
		"inflight_requests":           inflight,
		"handled_requests_since_boot": handled,
		"total_requests":              totalSummary.Requests,
		"total_ok":                    totalSummary.OK,
		"total_errors":                totalSummary.Errors,
		"error_rate_percent":          totalSummary.ErrorRatePercent,
		"avg_latency_ms":              totalSummary.AvgLatencyMs,
		"p95_latency_ms":              totalSummary.P95LatencyMs,
		"max_latency_ms":              totalSummary.MaxLatencyMs,
		"connections":                 connectionSummary,
		"routes":                      routes,
	}
}

func (m *RuntimeMonitor) resetTraffic() map[string]any {
	now := time.Now().UTC()
	m.mu.Lock()
	m.DayKey = now.Format("2006-01-02")
	m.TodayBaseline = newTrafficAggregate()
	m.TodaySession = newTrafficAggregate()
	m.Handled = 0
	m.StartTime = now
	m.Sessions = map[string]*RuntimeSessionInfo{}
	metricsDir := m.MetricsDir
	day := m.DayKey
	m.mu.Unlock()

	if strings.TrimSpace(metricsDir) != "" {
		_ = os.Remove(filepath.Join(metricsDir, "traffic-"+day+".json"))
		_ = os.Remove(filepath.Join(metricsDir, "traffic-"+day+".json.tmp"))
	}
	return map[string]any{
		"status":        "reset",
		"reset_at":      now,
		"metrics_dir":   metricsDir,
		"current_day":   day,
		"retains_db":    true,
		"retains_users": true,
	}
}

func summarizeRoute(route string, stats *TrafficRouteStats) TrafficRouteSummary {
	if stats == nil {
		stats = newTrafficRouteStats()
	}
	errorRate := 0.0
	avgLatency := 0.0
	if stats.Requests > 0 {
		errorRate = (float64(stats.Errors) / float64(stats.Requests)) * 100
		avgLatency = stats.TotalLatencyMs / float64(stats.Requests)
	}
	return TrafficRouteSummary{
		Route:            route,
		Requests:         stats.Requests,
		OK:               stats.OK,
		Errors:           stats.Errors,
		ErrorRatePercent: roundTo2(errorRate),
		AvgLatencyMs:     roundTo2(avgLatency),
		P95LatencyMs:     roundTo2(estimateP95Latency(stats.LatencyHistogram, stats.Requests)),
		MaxLatencyMs:     roundTo2(stats.MaxLatencyMs),
		StatusBuckets:    stats.StatusBuckets,
		ErrorBuckets:     stats.ErrorBuckets,
	}
}

func estimateP95Latency(histogram map[string]int64, totalRequests int64) float64 {
	if totalRequests <= 0 {
		return 0
	}
	target := int64(float64(totalRequests) * 0.95)
	if target <= 0 {
		target = 1
	}
	var running int64
	for _, bound := range trafficLatencyBounds {
		label := "<=" + strconv.Itoa(int(bound))
		running += histogram[label]
		if running >= target {
			return bound
		}
	}
	return 12000
}

func roundTo2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func (a *App) handleRuntimeTraffic(w http.ResponseWriter, r *http.Request) {
	windowDays := 90
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			windowDays = parsed
		}
	}
	writeJSON(w, http.StatusOK, a.runtimeMonitor.buildTrafficReport(windowDays))
}

func (a *App) handleRuntimeTrafficReset(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.runtimeMonitor.resetTraffic())
}
