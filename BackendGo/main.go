package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	internalKeyID          = "autoshopee-internal"
	sessionLifetimeMinutes = 30
	syncTokenTTLSeconds    = 240
	rotationMinSeconds     = 600
	rotationMaxSeconds     = 900
	publicKeyB64           = "IVQiSVHi/lGaURwMPl69hlysa5iL21fwjeFxzUwItf4="
)

type Config struct {
	BindAddress                 string
	DatabaseURL                 string
	MasterKey                   string
	InternalAPISecret           string
	ReleasePublicKeyB64         string
	SidecarURL                  string
	DevMode                     bool
	AllowInsecureDefaults       bool
	WorkerMetricsEnabled        bool
	RuntimeMetricsDir           string
	RuntimeMetricsRetentionDays int
	RuntimeMetricsFlushSeconds  int
}

type App struct {
	cfg                Config
	db                 *gorm.DB
	router             chi.Router
	httpClient         *http.Client
	verifyGuard        *VerifyAttemptGuard
	sessionGuard       *SessionChallengeGuard
	nonceCache         *NonceCache
	internalNonceCache *NonceCache
	runtimeMonitor     *RuntimeMonitor
}

type VerifyAttemptGuard struct {
	mu          sync.Mutex
	values      map[string]*VerifyAttemptState
	maxFailures int
	lockSeconds int
}

type VerifyAttemptState struct {
	Failures    int
	LockedUntil *time.Time
}

type SessionChallengeGuard struct {
	mu     sync.Mutex
	values map[string]*ChallengeState
}

type ChallengeState struct {
	BuildID              string
	SyncToken            string
	IssuedAt             time.Time
	Epoch                int
	TokenTTLSeconds      int
	RotationAfterSeconds int
	SessionExpiration    time.Time
}

type NonceCache struct {
	mu       sync.Mutex
	values   map[string]int64
	order    []string
	maxItems int
}

type RuntimeMonitor struct {
	mu             sync.Mutex
	ActiveRequests int
	Handled        int64
	StartTime      time.Time
	Enabled        bool
	MetricsDir     string
	RetentionDays  int
	FlushSeconds   int
	DayKey         string
	TodayBaseline  *TrafficAggregate
	TodaySession   *TrafficAggregate
}

type License struct {
	ID                uint   `gorm:"primaryKey"`
	Key               string `gorm:"uniqueIndex;size:128"`
	MachineID         string `gorm:"index;size:255"`
	AccountUsername   string `gorm:"index;size:255"`
	PlanCode          string `gorm:"size:255"`
	Source            string `gorm:"default:legacy;size:64"`
	Notes             string `gorm:"type:text"`
	IsActive          bool   `gorm:"default:true"`
	CreatedAt         time.Time
	ActivatedAt       *time.Time
	ExpirationDate    *time.Time
	DurationDays      int    `gorm:"default:30"`
	SessionID         string `gorm:"index;size:255"`
	SessionKey        string `gorm:"size:255"`
	SessionExpiration *time.Time
}

type ModuleVersion struct {
	ID            uint   `gorm:"primaryKey"`
	Name          string `gorm:"index;size:255"`
	Version       string `gorm:"size:64"`
	EncryptedCode string `gorm:"type:text"`
	HashChecksum  string `gorm:"size:128"`
	CreatedAt     time.Time
}

type WebUser struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;size:255"`
	Email        string `gorm:"uniqueIndex;size:255"`
	PasswordHash string `gorm:"size:512"`
	FullName     string `gorm:"size:255"`
	IsActive     bool   `gorm:"default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Notes        string `gorm:"type:text"`
}

type SubscriptionPlan struct {
	ID               uint   `gorm:"primaryKey"`
	Code             string `gorm:"uniqueIndex;size:255"`
	Name             string `gorm:"size:255"`
	DurationLabel    string `gorm:"size:255"`
	DurationDays     int    `gorm:"default:30"`
	MaxDevices       int    `gorm:"default:1"`
	IsActive         bool   `gorm:"default:true"`
	IsTrial          bool   `gorm:"default:false"`
	SortOrder        int    `gorm:"default:100"`
	PriceAmount      int    `gorm:"default:0"`
	Currency         string `gorm:"default:VND;size:16"`
	PriceNote        string `gorm:"size:255"`
	ExternalPriceRef string `gorm:"size:255"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CustomerSubscription struct {
	ID          uint   `gorm:"primaryKey"`
	UserID      uint   `gorm:"index"`
	PlanCode    string `gorm:"index;size:255"`
	Status      string `gorm:"index;default:active;size:64"`
	StartsAt    *time.Time
	ExpiresAt   *time.Time `gorm:"index"`
	MaxDevices  int        `gorm:"default:1"`
	PurchaseRef string     `gorm:"size:255"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Notes       string `gorm:"type:text"`
}

type DeviceActivation struct {
	ID                uint   `gorm:"primaryKey"`
	UserID            uint   `gorm:"index"`
	MachineID         string `gorm:"index;size:255"`
	DeviceName        string `gorm:"size:255"`
	DeviceBindingHash string `gorm:"size:255"`
	Status            string `gorm:"index;default:pending;size:64"`
	ApprovedAt        *time.Time
	BindingUpdatedAt  *time.Time
	LastLoginAt       *time.Time
	LicenseID         *uint `gorm:"index"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Notes             string `gorm:"type:text"`
}

type LicenseCheckRequest struct {
	Key              string         `json:"key"`
	MachineID        string         `json:"machine_id"`
	BuildID          string         `json:"build_id"`
	BuildAttestation map[string]any `json:"build_attestation"`
}

type PublicLoginRequest struct {
	Username         string         `json:"username"`
	Password         string         `json:"password"`
	MachineID        string         `json:"machine_id"`
	BuildID          string         `json:"build_id"`
	BuildAttestation map[string]any `json:"build_attestation"`
	DeviceName       string         `json:"device_name"`
	DeviceBinding    string         `json:"device_binding"`
}

type AccessKeyBootstrapRequest struct {
	AccessKey        string         `json:"access_key"`
	MachineID        string         `json:"machine_id"`
	BuildID          string         `json:"build_id"`
	BuildAttestation map[string]any `json:"build_attestation"`
	DeviceName       string         `json:"device_name"`
	DeviceBinding    string         `json:"device_binding"`
}

type SessionAuthRequest struct {
	BuildID   string `json:"build_id"`
	SessionID string `json:"session_id"`
	MachineID string `json:"machine_id"`
	SyncToken string `json:"sync_token"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type FetchModuleRequest struct {
	SessionAuthRequest
	ModuleName string `json:"module_name"`
}

type PuzzleSolveRequest struct {
	SessionAuthRequest
	Type       string `json:"type"`
	Challenge  string `json:"challenge"`
	ModuleName string `json:"module_name"`
}

type CreateLicenseReq struct {
	Key          string `json:"key"`
	DurationDays int    `json:"duration_days"`
	Description  string `json:"description"`
}

type ModuleUploadRequest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	CodeContent string `json:"code_content"`
}

type UpsertWebUserReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	IsActive bool   `json:"is_active"`
	Notes    string `json:"notes"`
}

type UpsertPlanReq struct {
	Code             string `json:"code"`
	Name             string `json:"name"`
	DurationLabel    string `json:"duration_label"`
	DurationDays     int    `json:"duration_days"`
	MaxDevices       int    `json:"max_devices"`
	IsActive         bool   `json:"is_active"`
	IsTrial          bool   `json:"is_trial"`
	SortOrder        int    `json:"sort_order"`
	PriceAmount      int    `json:"price_amount"`
	Currency         string `json:"currency"`
	PriceNote        string `json:"price_note"`
	ExternalPriceRef string `json:"external_price_ref"`
}

type UpdatePlanPriceReq struct {
	Code             string `json:"code"`
	PriceAmount      int    `json:"price_amount"`
	Currency         string `json:"currency"`
	PriceNote        string `json:"price_note"`
	ExternalPriceRef string `json:"external_price_ref"`
}

type SeedDefaultPlansReq struct {
	OverwriteExisting bool `json:"overwrite_existing"`
	OverwritePrices   bool `json:"overwrite_prices"`
}

type GrantSubscriptionReq struct {
	UserIdentity          string `json:"user_identity"`
	PlanCode              string `json:"plan_code"`
	DurationDays          *int   `json:"duration_days"`
	MaxDevices            *int   `json:"max_devices"`
	ExpiresAt             string `json:"expires_at"`
	PurchaseRef           string `json:"purchase_ref"`
	Notes                 string `json:"notes"`
	Status                string `json:"status"`
	ReplaceExistingActive bool   `json:"replace_existing_active"`
	AllowRepeatTrial      bool   `json:"allow_repeat_trial"`
}

type AuthorizeDeviceReq struct {
	UserIdentity string `json:"user_identity"`
	MachineID    string `json:"machine_id"`
	DeviceName   string `json:"device_name"`
	Status       string `json:"status"`
	Notes        string `json:"notes"`
}

type RevokeDeviceReq struct {
	UserIdentity string `json:"user_identity"`
	MachineID    string `json:"machine_id"`
}

type WorkerScaleReq struct {
	Action  string `json:"action"`
	Count   int    `json:"count"`
	Persist bool   `json:"persist"`
}

type sidecarPasswordHashResp struct {
	PasswordHash string `json:"password_hash"`
}

type sidecarPasswordVerifyResp struct {
	Valid bool `json:"valid"`
}

type sidecarEncryptModuleResp struct {
	EncryptedCode string `json:"encrypted_code"`
	Checksum      string `json:"checksum"`
}

type sidecarProcessModuleResp struct {
	Checksum      string `json:"checksum"`
	FragmentSeal  string `json:"fragment_seal"`
	EncryptedCode string `json:"encrypted_code"`
}

var defaultPlanCatalog = []SubscriptionPlan{
	{Code: "trial-7d", Name: "Free 7 ngay", DurationLabel: "7 ngay dung thu", DurationDays: 7, MaxDevices: 1, IsActive: true, IsTrial: true, SortOrder: 10, PriceAmount: 0, Currency: "VND", PriceNote: "Goi dung thu mien phi 7 ngay", ExternalPriceRef: "trial-7d"},
	{Code: "plan-1m", Name: "Goi 1 thang", DurationLabel: "1 thang", DurationDays: 30, MaxDevices: 1, IsActive: true, IsTrial: false, SortOrder: 20, PriceAmount: 0, Currency: "VND", PriceNote: "Gia co the cap nhat tu website", ExternalPriceRef: "plan-1m"},
	{Code: "plan-3m", Name: "Goi 3 thang", DurationLabel: "3 thang", DurationDays: 90, MaxDevices: 1, IsActive: true, IsTrial: false, SortOrder: 30, PriceAmount: 0, Currency: "VND", PriceNote: "Gia co the cap nhat tu website", ExternalPriceRef: "plan-3m"},
	{Code: "plan-6m", Name: "Goi 6 thang", DurationLabel: "6 thang", DurationDays: 180, MaxDevices: 1, IsActive: true, IsTrial: false, SortOrder: 40, PriceAmount: 0, Currency: "VND", PriceNote: "Gia co the cap nhat tu website", ExternalPriceRef: "plan-6m"},
	{Code: "plan-12m", Name: "Goi 12 thang", DurationLabel: "12 thang", DurationDays: 365, MaxDevices: 1, IsActive: true, IsTrial: false, SortOrder: 50, PriceAmount: 0, Currency: "VND", PriceNote: "Gia co the cap nhat tu website", ExternalPriceRef: "plan-12m"},
}

func main() {
	cfg := loadConfig()
	db, err := openDatabase(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connect failed: %v", err)
	}
	if err := migrateDatabase(db); err != nil {
		log.Fatalf("auto migrate failed: %v", err)
	}
	app := newApp(cfg, db)
	if err := app.ensureDefaultPlans(false, false); err != nil {
		log.Fatalf("seed plans failed: %v", err)
	}
	server := &http.Server{
		Addr:         cfg.BindAddress,
		Handler:      app.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("Auto-Shopee hybrid Go backend listening on %s", cfg.BindAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func newApp(cfg Config, db *gorm.DB) *App {
	app := &App{
		cfg:                cfg,
		db:                 db,
		httpClient:         &http.Client{Timeout: 20 * time.Second},
		verifyGuard:        &VerifyAttemptGuard{values: map[string]*VerifyAttemptState{}, maxFailures: 10, lockSeconds: 1800},
		sessionGuard:       &SessionChallengeGuard{values: map[string]*ChallengeState{}},
		nonceCache:         NewNonceCache(20000),
		internalNonceCache: NewNonceCache(20000),
		runtimeMonitor:     NewRuntimeMonitor(cfg),
	}
	router := chi.NewRouter()
	router.Use(app.trackRuntimeMiddleware)
	router.Get("/", app.handleRoot)
	router.Get("/api/public/health", app.handleHealth)
	router.Get("/api/public/plans", app.handlePublicPlans)
	router.Post("/verify_license", app.handleVerifyLicense)
	router.Post("/api/public/login", app.handlePublicLogin)
	router.Post("/api/public/access-key-login", app.handleAccessKeyLogin)
	router.Post("/fetch_module", app.handleFetchModule)
	router.Post("/heartbeat", app.handleHeartbeat)
	router.Post("/puzzle/solve", app.handleSolvePuzzle)

	router.Route("/api/internal", func(r chi.Router) {
		r.Use(app.internalAuthMiddleware)
		r.Post("/create_license", app.handleCreateLicense)
		r.Post("/users/upsert", app.handleUpsertUser)
		r.Get("/users/status", app.handleUserStatus)
		r.Post("/plans/upsert", app.handleUpsertPlan)
		r.Get("/plans", app.handleListPlans)
		r.Post("/plans/seed-defaults", app.handleSeedDefaultPlans)
		r.Post("/plans/update-price", app.handleUpdatePlanPrice)
		r.Post("/subscriptions/grant", app.handleGrantSubscription)
		r.Post("/devices/authorize", app.handleAuthorizeDevice)
		r.Post("/devices/revoke", app.handleRevokeDevice)
		r.Post("/reset_hwid", app.handleResetHWID)
		r.Get("/stats", app.handleStats)
		r.Get("/runtime/workers", app.handleRuntimeWorkers)
		r.Get("/runtime/traffic", app.handleRuntimeTraffic)
		r.Post("/runtime/workers/scale", app.handleRuntimeWorkersScale)
		r.Post("/upload_module", app.handleUploadModule)
	})
	app.router = router
	return app
}

func loadConfig() Config {
	return Config{
		BindAddress:                 getenv("BACKEND_BIND", "0.0.0.0:8000"),
		DatabaseURL:                 getenv("DATABASE_URL", "postgresql://autoshopee:autoshopee@localhost:5432/autoshopee?sslmode=disable"),
		MasterKey:                   getenv("MASTER_KEY", ""),
		InternalAPISecret:           getenv("INTERNAL_API_SECRET", ""),
		ReleasePublicKeyB64:         getenv("RELEASE_PUBLIC_KEY_B64", publicKeyB64),
		SidecarURL:                  getenv("BACKEND_PY_SIDECAR_URL", "http://127.0.0.1:9801"),
		DevMode:                     getenvBool("DEV_MODE", false),
		AllowInsecureDefaults:       getenvBool("ALLOW_INSECURE_DEFAULTS", false),
		WorkerMetricsEnabled:        getenvBool("WORKER_METRICS_ENABLED", true),
		RuntimeMetricsDir:           getenv("RUNTIME_METRICS_DIR", "logs/runtime-metrics"),
		RuntimeMetricsRetentionDays: maxInt(getenvInt("RUNTIME_METRICS_RETENTION_DAYS", 90), 1),
		RuntimeMetricsFlushSeconds:  maxInt(getenvInt("RUNTIME_METRICS_FLUSH_SECONDS", 30), 5),
	}
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func getenvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func NewNonceCache(maxItems int) *NonceCache {
	return &NonceCache{values: map[string]int64{}, order: []string{}, maxItems: maxItems}
}

func (c *NonceCache) Consume(nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(nonce) == "" {
		return false
	}
	if _, exists := c.values[nonce]; exists {
		return false
	}
	c.values[nonce] = time.Now().UTC().Unix()
	c.order = append(c.order, nonce)
	for len(c.order) > c.maxItems {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.values, oldest)
	}
	return true
}

func (g *VerifyAttemptGuard) cleanup(now time.Time) {
	for scope, state := range g.values {
		if state.LockedUntil != nil && !state.LockedUntil.After(now) {
			delete(g.values, scope)
		}
	}
}

func (g *VerifyAttemptGuard) Check(scope string) *time.Time {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	now := time.Now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanup(now)
	state := g.values[scope]
	if state == nil || state.LockedUntil == nil || !state.LockedUntil.After(now) {
		return nil
	}
	copyValue := *state.LockedUntil
	return &copyValue
}

func (g *VerifyAttemptGuard) RegisterFailure(scope string) *time.Time {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	now := time.Now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanup(now)
	state := g.values[scope]
	if state == nil {
		state = &VerifyAttemptState{}
		g.values[scope] = state
	}
	state.Failures++
	if state.Failures >= g.maxFailures {
		lock := now.Add(time.Duration(g.lockSeconds) * time.Second)
		state.LockedUntil = &lock
		copyValue := lock
		return &copyValue
	}
	return nil
}

func (g *VerifyAttemptGuard) Clear(scope string) {
	if strings.TrimSpace(scope) == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.values, scope)
}

func (g *SessionChallengeGuard) Bootstrap(sessionID string, sessionExpiration time.Time, buildID string) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := &ChallengeState{
		BuildID:              fallbackString(buildID, "DEV-SOURCE"),
		SyncToken:            uuid.NewString(),
		IssuedAt:             time.Now().UTC(),
		Epoch:                1,
		TokenTTLSeconds:      syncTokenTTLSeconds,
		RotationAfterSeconds: rotationMinSeconds + mathrand.Intn(rotationMaxSeconds-rotationMinSeconds+1),
		SessionExpiration:    sessionExpiration.UTC(),
	}
	g.values[sessionID] = state
	return challengeStateToMap(state)
}

func (g *SessionChallengeGuard) Refresh(sessionID string, sessionExpiration time.Time) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.values[sessionID]
	if state == nil {
		return nil
	}
	state.SyncToken = uuid.NewString()
	state.IssuedAt = time.Now().UTC()
	state.Epoch++
	state.SessionExpiration = sessionExpiration.UTC()
	if state.RotationAfterSeconds == 0 {
		state.RotationAfterSeconds = rotationMinSeconds + mathrand.Intn(rotationMaxSeconds-rotationMinSeconds+1)
	}
	return challengeStateToMap(state)
}

func (g *SessionChallengeGuard) Validate(sessionID, syncToken string, allowStale bool) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.values[sessionID]
	if state == nil || state.SyncToken != syncToken {
		return nil
	}
	if !allowStale && time.Since(state.IssuedAt) > time.Duration(state.TokenTTLSeconds)*time.Second {
		return nil
	}
	return challengeStateToMap(state)
}

func (g *SessionChallengeGuard) Clear(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.values, sessionID)
}

func challengeStateToMap(state *ChallengeState) map[string]any {
	return map[string]any{
		"build_id":               state.BuildID,
		"sync_token":             state.SyncToken,
		"issued_at":              state.IssuedAt,
		"epoch":                  state.Epoch,
		"token_ttl_seconds":      state.TokenTTLSeconds,
		"rotation_after_seconds": state.RotationAfterSeconds,
		"session_expiration":     state.SessionExpiration,
	}
}

func (m *RuntimeMonitor) started() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rolloverIfNeededLocked(time.Now().UTC())
	m.ActiveRequests++
}

func (m *RuntimeMonitor) finished(method string, route string, status int, elapsed time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rolloverIfNeededLocked(time.Now().UTC())
	if m.ActiveRequests > 0 {
		m.ActiveRequests--
	}
	m.Handled++
	m.recordRequestLocked(method, route, status, elapsed)
}

func (a *App) trackRuntimeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := newStatusRecorder(w)
		startedAt := time.Now()
		a.runtimeMonitor.started()
		next.ServeHTTP(recorder, r)
		route := r.URL.Path
		if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
			if pattern := strings.TrimSpace(routeCtx.RoutePattern()); pattern != "" {
				route = pattern
			}
		}
		a.runtimeMonitor.finished(r.Method, route, recorder.Status(), time.Since(startedAt))
	})
}

func (a *App) internalAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != internalKeyID {
			writeError(w, http.StatusForbidden, "Forbidden: Invalid internal key id")
			return
		}
		if strings.TrimSpace(a.cfg.InternalAPISecret) == "" {
			writeError(w, http.StatusServiceUnavailable, "Internal API secret is not configured")
			return
		}
		timestamp := r.Header.Get("X-Internal-Timestamp")
		nonce := r.Header.Get("X-Internal-Nonce")
		signature := r.Header.Get("X-Internal-Signature")
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		bodyHash := sha256HexForInternalBody(bodyBytes)
		message := fmt.Sprintf("%s|%s|%s|%s|%s", strings.ToUpper(r.Method), r.URL.Path, timestamp, nonce, bodyHash)
		expected := signHMAC(a.cfg.InternalAPISecret, message)
		if !hmac.Equal([]byte(expected), []byte(signature)) {
			writeError(w, http.StatusForbidden, "Forbidden: Invalid internal signature")
			return
		}
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid internal timestamp")
			return
		}
		if math.Abs(float64(time.Now().UTC().Unix()-ts)) > 300 {
			writeError(w, http.StatusForbidden, "Internal request timestamp out of sync")
			return
		}
		if !a.internalNonceCache.Consume(nonce) {
			writeError(w, http.StatusForbidden, "Internal request replay detected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "Server running", "time": time.Now().UTC()})
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC()})
}

func (a *App) handlePublicPlans(w http.ResponseWriter, r *http.Request) {
	var plans []SubscriptionPlan
	if err := a.db.Where("is_active = ?", true).Order("sort_order asc, duration_days asc, id asc").Find(&plans).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(plans) == 0 {
		if err := a.ensureDefaultPlans(false, false); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = a.db.Where("is_active = ?", true).Order("sort_order asc, duration_days asc, id asc").Find(&plans).Error
	}
	items := make([]map[string]any, 0, len(plans))
	for _, plan := range plans {
		items = append(items, serializePlan(plan))
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": items})
}

func (a *App) handleVerifyLicense(w http.ResponseWriter, r *http.Request) {
	var req LicenseCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	key := strings.TrimSpace(req.Key)
	machineID := normalizeMachineID(req.MachineID)
	if key == "" || machineID == "" {
		writeError(w, http.StatusBadRequest, "Missing key or machine_id")
		return
	}
	buildID, _, err := a.verifyBuildAttestation(fallbackString(req.BuildID, "DEV-SOURCE"), req.BuildAttestation, r)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	scopes := a.buildAuthScopeKeys(machineID, r, "", key)
	if locked := a.getAuthLock(scopes); locked != nil {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Machine locked until %s after too many failed license attempts", locked.Format(time.RFC3339)))
		return
	}
	licenseItem, err := a.getLicenseByKey(key)
	if err == nil {
		err = a.validateLicenseBinding(licenseItem, machineID)
	}
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok && httpErr.StatusCode == http.StatusForbidden && httpErr.Detail != "License expired" {
			a.registerAuthFailure(scopes, httpErr.Detail, httpErr.StatusCode)
		}
		writeHTTPError(w, err)
		return
	}
	accountContext, err := a.buildAccountContextFromLicense(licenseItem, machineID, "", "")
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	a.clearAuthFailures(scopes)
	response, err := a.issueSessionForLicense(licenseItem, buildID, accountContext)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handlePublicLogin(w http.ResponseWriter, r *http.Request) {
	var req PublicLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	username := normalizeIdentity(req.Username)
	password := req.Password
	machineID := normalizeMachineID(req.MachineID)
	if username == "" || password == "" || machineID == "" {
		writeError(w, http.StatusBadRequest, "Missing username, password, or machine_id")
		return
	}
	buildID, _, err := a.verifyBuildAttestation(fallbackString(req.BuildID, "DEV-SOURCE"), req.BuildAttestation, r)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	scopes := a.buildAuthScopeKeys(machineID, r, username, "")
	if locked := a.getAuthLock(scopes); locked != nil {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Machine locked until %s after too many failed login attempts", locked.Format(time.RFC3339)))
		return
	}
	user, err := a.getUserByIdentity(username)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	if user == nil {
		a.registerAuthFailure(scopes, "Invalid username/email or password", http.StatusUnauthorized)
		writeError(w, http.StatusUnauthorized, "Invalid username/email or password")
		return
	}
	valid, err := a.sidecarVerifyPassword(password, user.PasswordHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !valid {
		a.registerAuthFailure(scopes, "Invalid username/email or password", http.StatusUnauthorized)
		writeError(w, http.StatusUnauthorized, "Invalid username/email or password")
		return
	}
	if !user.IsActive {
		writeError(w, http.StatusForbidden, "Account is disabled")
		return
	}
	subscription, err := a.getActiveSubscription(user.ID)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	if subscription == nil {
		writeError(w, 402, "Tai khoan chua co goi su dung hoac goi da het han. Vui long mua goi tren website.")
		return
	}
	device, err := a.getDeviceActivation(user.ID, machineID)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	if device == nil || strings.ToLower(device.Status) != "active" {
		writeError(w, http.StatusForbidden, "Thiet bi nay chua duoc kich hoat cho tai khoan. Vui long vao website de dang ky machine ID.")
		return
	}
	if err := a.enforceDeviceBinding(device, req.DeviceBinding); err != nil {
		writeHTTPError(w, err)
		return
	}
	if name := strings.TrimSpace(req.DeviceName); name != "" {
		device.DeviceName = name
	}
	now := time.Now().UTC()
	device.LastLoginAt = &now
	if device.ApprovedAt == nil {
		device.ApprovedAt = &now
	}
	if err := a.db.Save(device).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	licenseItem, err := a.ensureDeviceAccessLicense(user, subscription, device)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	plan, _ := a.getPlanByCode(subscription.PlanCode)
	accountContext := buildAccountContext(*user, *subscription, *device, plan)
	a.clearAuthFailures(scopes)
	response, err := a.issueSessionForLicense(licenseItem, buildID, accountContext)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleAccessKeyLogin(w http.ResponseWriter, r *http.Request) {
	var req AccessKeyBootstrapRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	accessKey := strings.TrimSpace(req.AccessKey)
	machineID := normalizeMachineID(req.MachineID)
	if accessKey == "" || machineID == "" {
		writeError(w, http.StatusBadRequest, "Missing access_key or machine_id")
		return
	}
	buildID, _, err := a.verifyBuildAttestation(fallbackString(req.BuildID, "DEV-SOURCE"), req.BuildAttestation, r)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	scopes := a.buildAuthScopeKeys(machineID, r, "", accessKey)
	if locked := a.getAuthLock(scopes); locked != nil {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Machine locked until %s after too many failed login attempts", locked.Format(time.RFC3339)))
		return
	}
	licenseItem, err := a.getLicenseByKey(accessKey)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	if err := a.validateLicenseBinding(licenseItem, machineID); err != nil {
		if httpErr, ok := err.(*HTTPError); ok && (httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
			a.registerAuthFailure(scopes, httpErr.Detail, httpErr.StatusCode)
		}
		writeHTTPError(w, err)
		return
	}
	accountContext, err := a.buildAccountContextFromLicense(licenseItem, machineID, req.DeviceName, req.DeviceBinding)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok && (httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
			a.registerAuthFailure(scopes, httpErr.Detail, httpErr.StatusCode)
		}
		writeHTTPError(w, err)
		return
	}
	a.clearAuthFailures(scopes)
	response, err := a.issueSessionForLicense(licenseItem, buildID, accountContext)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req SessionAuthRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	licenseItem, challengeState, err := a.validateSessionRequest(req, "", true)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	refreshed := a.sessionGuard.Refresh(req.SessionID, licenseItem.SessionExpiration.UTC())
	if refreshed == nil {
		writeError(w, http.StatusUnauthorized, "Session challenge expired")
		return
	}
	token := refreshed["sync_token"].(string)
	response := map[string]any{
		"status":                 "ok",
		"sync_token":             token,
		"signature":              signHMAC(licenseItem.SessionKey, token),
		"session_expiration":     licenseItem.SessionExpiration,
		"response_type":          "heartbeat",
		"session_id":             req.SessionID,
		"session_epoch":          refreshed["epoch"],
		"sync_token_ttl_seconds": refreshed["token_ttl_seconds"],
		"rotation_after_seconds": refreshed["rotation_after_seconds"],
		"issued_at":              currentTimestamp(),
	}
	response["response_signature"] = signServerResponse(licenseItem.SessionKey, response)
	_ = challengeState
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleFetchModule(w http.ResponseWriter, r *http.Request) {
	var req FetchModuleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	licenseItem, challengeState, err := a.validateSessionRequest(req.SessionAuthRequest, req.ModuleName, false)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	var module ModuleVersion
	if err := a.db.Where("name = ?", req.ModuleName).Order("id desc").First(&module).Error; err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Module %s not found", req.ModuleName))
		return
	}
	sidecarPayload := map[string]any{
		"encrypted_code": module.EncryptedCode,
		"module_name":    req.ModuleName,
		"session_id":     req.SessionID,
		"session_key":    licenseItem.SessionKey,
		"session_epoch":  challengeState["epoch"],
	}
	var sidecarResp sidecarProcessModuleResp
	if err := a.callSidecar("/process-module", sidecarPayload, &sidecarResp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]any{
		"name":           module.Name,
		"version":        module.Version,
		"checksum":       sidecarResp.Checksum,
		"fragment_seal":  sidecarResp.FragmentSeal,
		"encrypted_code": sidecarResp.EncryptedCode,
		"response_type":  "module",
		"module_name":    req.ModuleName,
		"session_id":     req.SessionID,
		"sync_token":     req.SyncToken,
		"session_epoch":  challengeState["epoch"],
		"issued_at":      currentTimestamp(),
	}
	response["response_signature"] = signServerResponse(licenseItem.SessionKey, response)
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleSolvePuzzle(w http.ResponseWriter, r *http.Request) {
	var req PuzzleSolveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	expectedScope := fmt.Sprintf("puzzle:%s:%s", req.Type, req.Challenge)
	if req.ModuleName != expectedScope {
		writeError(w, http.StatusForbidden, "Invalid puzzle scope")
		return
	}
	licenseItem, challengeState, err := a.validateSessionRequest(req.SessionAuthRequest, req.ModuleName, false)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	var result any
	switch req.Type {
	case "api_offset":
		value, _ := strconv.Atoi(req.Challenge)
		result = (value * 3) % 7
	case "magic_token":
		salt := licenseItem.SessionKey
		if len(salt) > 5 {
			salt = salt[:5]
		}
		sum := md5Hex(req.Challenge + salt)
		result = sum[:16]
	case "param_shuffle":
		result = []int{0, 1, 2}
	case "status_map":
		statusMap := map[string]int{"ALL": 100, "UNPAID": 200, "TO_SHIP": 300, "SHIPPING": 400, "COMPLETED": 500, "CANCELLED": 100, "TO_RETURN": 100}
		value, ok := statusMap[req.Challenge]
		if !ok {
			value = 100
		}
		result = value
	case "flash_window":
		result = 7
	case "chat_limit", "sync_batch", "rating_limit", "product_limit":
		saltVal := new(bigHash).fromHex(md5Hex(licenseItem.SessionKey))
		limit := 50
		retries := 0
		if req.Type == "rating_limit" || req.Type == "product_limit" {
			limit = 20
		}
		if req.Type == "chat_limit" {
			retries = 3
		}
		result = map[string]any{"limit": limit, "retries": retries, "magic_salt": saltVal.String()}
	case "ui_unlock":
		if req.Challenge == "sidebar_init" {
			result = "7f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c"
		} else {
			result = "INVALID"
		}
	default:
		result = nil
	}
	response := map[string]any{
		"status":        "ok",
		"solution":      result,
		"response_type": "puzzle",
		"type":          req.Type,
		"challenge":     req.Challenge,
		"session_id":    req.SessionID,
		"sync_token":    req.SyncToken,
		"session_epoch": challengeState["epoch"],
		"issued_at":     currentTimestamp(),
	}
	response["response_signature"] = signServerResponse(licenseItem.SessionKey, response)
	writeJSON(w, http.StatusOK, response)
}

// Internal handlers
func (a *App) handleCreateLicense(w http.ResponseWriter, r *http.Request) {
	var req CreateLicenseReq
	if !decodeJSON(w, r, &req) {
		return
	}
	license := License{Key: strings.TrimSpace(req.Key), DurationDays: maxInt(req.DurationDays, 30), Source: "legacy", Notes: req.Description, IsActive: true}
	if err := a.db.Create(&license).Error; err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "key": req.Key})
}

func (a *App) handleUpsertUser(w http.ResponseWriter, r *http.Request) {
	var req UpsertWebUserReq
	if !decodeJSON(w, r, &req) {
		return
	}
	username := normalizeIdentity(req.Username)
	email := normalizeIdentity(req.Email)
	if username == "" || email == "" {
		writeError(w, http.StatusBadRequest, "username and email are required")
		return
	}
	var user WebUser
	creating := false
	if err := a.db.Where("username = ? OR email = ?", username, email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			creating = true
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if creating {
		if strings.TrimSpace(req.Password) == "" {
			writeError(w, http.StatusBadRequest, "password is required for new users")
			return
		}
		passwordHash, err := a.sidecarHashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user = WebUser{Username: username, Email: email, PasswordHash: passwordHash, FullName: strings.TrimSpace(req.FullName), IsActive: req.IsActive, Notes: strings.TrimSpace(req.Notes)}
		if err := a.db.Create(&user).Error; err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		oldUsername := normalizeIdentity(user.Username)
		user.Username = username
		user.Email = email
		user.FullName = strings.TrimSpace(req.FullName)
		user.IsActive = req.IsActive
		user.Notes = strings.TrimSpace(req.Notes)
		if strings.TrimSpace(req.Password) != "" {
			passwordHash, err := a.sidecarHashPassword(req.Password)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			user.PasswordHash = passwordHash
		}
		if err := a.db.Save(&user).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if oldUsername != "" && oldUsername != username {
			_ = a.db.Model(&License{}).Where("account_username = ? AND source = ?", oldUsername, "account_portal").Update("account_username", username).Error
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ternary(creating, "created", "updated"), "user_id": user.ID, "username": user.Username, "email": user.Email, "is_active": user.IsActive})
}

func (a *App) handleUpsertPlan(w http.ResponseWriter, r *http.Request) {
	var req UpsertPlanReq
	if !decodeJSON(w, r, &req) {
		return
	}
	code := strings.ToLower(strings.TrimSpace(req.Code))
	if code == "" {
		writeError(w, http.StatusBadRequest, "plan code is required")
		return
	}
	plan, _ := a.getPlanByCode(code)
	creating := plan == nil
	if creating {
		plan = &SubscriptionPlan{Code: code}
	}
	plan.Name = strings.TrimSpace(req.Name)
	plan.DurationLabel = strings.TrimSpace(req.DurationLabel)
	plan.DurationDays = maxInt(req.DurationDays, 1)
	plan.MaxDevices = maxInt(req.MaxDevices, 1)
	plan.IsActive = req.IsActive
	plan.IsTrial = req.IsTrial
	plan.SortOrder = maxInt(req.SortOrder, 1)
	plan.PriceAmount = maxInt(req.PriceAmount, 0)
	plan.Currency = strings.ToUpper(fallbackString(req.Currency, "VND"))
	plan.PriceNote = strings.TrimSpace(req.PriceNote)
	plan.ExternalPriceRef = strings.TrimSpace(req.ExternalPriceRef)
	if err := a.db.Save(plan).Error; err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ternary(creating, "created", "updated"), "plan": serializePlan(*plan)})
}

func (a *App) handleListPlans(w http.ResponseWriter, r *http.Request) {
	includeInactive := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_inactive"))) != "false"
	query := a.db.Order("sort_order asc, duration_days asc, id asc")
	if !includeInactive {
		query = query.Where("is_active = ?", true)
	}
	var plans []SubscriptionPlan
	if err := query.Find(&plans).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(plans))
	for _, plan := range plans {
		items = append(items, serializePlan(plan))
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": items})
}

func (a *App) handleSeedDefaultPlans(w http.ResponseWriter, r *http.Request) {
	var req SeedDefaultPlansReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.ensureDefaultPlans(req.OverwriteExisting, req.OverwritePrices); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.handleListPlans(w, r)
}

func (a *App) handleUpdatePlanPrice(w http.ResponseWriter, r *http.Request) {
	var req UpdatePlanPriceReq
	if !decodeJSON(w, r, &req) {
		return
	}
	plan, err := a.getPlanByCode(req.Code)
	if err != nil || plan == nil {
		writeError(w, http.StatusNotFound, "Plan not found")
		return
	}
	plan.PriceAmount = maxInt(req.PriceAmount, 0)
	plan.Currency = strings.ToUpper(fallbackString(req.Currency, "VND"))
	if strings.TrimSpace(req.PriceNote) != "" {
		plan.PriceNote = strings.TrimSpace(req.PriceNote)
	}
	if strings.TrimSpace(req.ExternalPriceRef) != "" {
		plan.ExternalPriceRef = strings.TrimSpace(req.ExternalPriceRef)
	}
	if err := a.db.Save(plan).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "plan": serializePlan(*plan)})
}

func (a *App) handleGrantSubscription(w http.ResponseWriter, r *http.Request) {
	var req GrantSubscriptionReq
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := a.getUserByIdentity(req.UserIdentity)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	plan, err := a.getPlanByCode(req.PlanCode)
	if err != nil || plan == nil || !plan.IsActive {
		writeError(w, http.StatusNotFound, "Plan not found or inactive")
		return
	}
	startsAt := time.Now().UTC()
	durationDays := plan.DurationDays
	if req.DurationDays != nil && *req.DurationDays > 0 {
		durationDays = *req.DurationDays
	}
	expiresAt := startsAt.Add(time.Duration(durationDays) * 24 * time.Hour)
	if strings.TrimSpace(req.ExpiresAt) != "" {
		if parsed, err := parseOptionalTime(req.ExpiresAt); err == nil && parsed != nil {
			expiresAt = parsed.UTC()
		}
	}
	status := fallbackString(strings.ToLower(strings.TrimSpace(req.Status)), "active")
	if plan.IsTrial && !req.AllowRepeatTrial {
		var count int64
		_ = a.db.Model(&CustomerSubscription{}).Where("user_id = ? AND plan_code = ?", user.ID, plan.Code).Count(&count).Error
		if count > 0 {
			writeError(w, http.StatusConflict, "User da su dung goi dung thu nay truoc do")
			return
		}
	}
	var subscription CustomerSubscription
	creating := false
	if err := a.db.Where("user_id = ? AND plan_code = ?", user.ID, plan.Code).Order("id desc").First(&subscription).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			creating = true
			subscription = CustomerSubscription{UserID: user.ID, PlanCode: plan.Code}
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	maxDevices := plan.MaxDevices
	if req.MaxDevices != nil && *req.MaxDevices > 0 {
		maxDevices = *req.MaxDevices
	}
	subscription.Status = status
	subscription.StartsAt = &startsAt
	subscription.ExpiresAt = &expiresAt
	subscription.MaxDevices = maxDevices
	subscription.PurchaseRef = strings.TrimSpace(req.PurchaseRef)
	subscription.Notes = strings.TrimSpace(req.Notes)
	if err := a.db.Save(&subscription).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status == "active" && req.ReplaceExistingActive {
		_ = a.db.Model(&CustomerSubscription{}).Where("user_id = ? AND status = ? AND id <> ?", user.ID, "active", subscription.ID).Updates(map[string]any{"status": "superseded", "updated_at": time.Now().UTC()}).Error
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ternary(creating, "created", "updated"), "user_id": user.ID, "plan_code": subscription.PlanCode, "subscription_status": subscription.Status, "expires_at": subscription.ExpiresAt, "max_devices": subscription.MaxDevices, "plan": serializePlan(*plan)})
}

func (a *App) handleAuthorizeDevice(w http.ResponseWriter, r *http.Request) {
	var req AuthorizeDeviceReq
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := a.getUserByIdentity(req.UserIdentity)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	machineID := normalizeMachineID(req.MachineID)
	if machineID == "" {
		writeError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	subscription, err := a.getActiveSubscription(user.ID)
	if err != nil || subscription == nil {
		writeError(w, http.StatusBadRequest, "User has no active subscription")
		return
	}
	device, err := a.getDeviceActivation(user.ID, machineID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	requestedStatus := fallbackString(strings.ToLower(strings.TrimSpace(req.Status)), "active")
	var activeCount int64
	_ = a.db.Model(&DeviceActivation{}).Where("user_id = ? AND status = ?", user.ID, "active").Count(&activeCount).Error
	if requestedStatus == "active" {
		effectiveActive := activeCount
		if device != nil && strings.ToLower(device.Status) == "active" {
			effectiveActive = maxInt64(0, effectiveActive-1)
		}
		if effectiveActive >= int64(maxInt(subscription.MaxDevices, 1)) {
			writeError(w, http.StatusConflict, "Max device limit reached for this subscription")
			return
		}
	}
	now := time.Now().UTC()
	if device == nil {
		device = &DeviceActivation{UserID: user.ID, MachineID: machineID, DeviceName: strings.TrimSpace(req.DeviceName), Status: requestedStatus, Notes: strings.TrimSpace(req.Notes)}
		if requestedStatus == "active" {
			device.ApprovedAt = &now
		}
	} else {
		if name := strings.TrimSpace(req.DeviceName); name != "" {
			device.DeviceName = name
		}
		device.Status = requestedStatus
		device.Notes = strings.TrimSpace(req.Notes)
		if requestedStatus == "active" {
			device.ApprovedAt = &now
		}
	}
	if err := a.db.Save(device).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	licenseItem, err := a.ensureDeviceAccessLicense(user, subscription, device)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": device.Status, "user_id": user.ID, "machine_id": device.MachineID, "device_name": device.DeviceName, "access_key": licenseItem.Key, "subscription_expires_at": subscription.ExpiresAt})
}

func (a *App) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	var req RevokeDeviceReq
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := a.getUserByIdentity(req.UserIdentity)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	device, err := a.getDeviceActivation(user.ID, normalizeMachineID(req.MachineID))
	if err != nil || device == nil {
		writeError(w, http.StatusNotFound, "Device not found")
		return
	}
	now := time.Now().UTC()
	device.Status = "revoked"
	device.UpdatedAt = now
	device.LastLoginAt = &now
	if device.LicenseID != nil {
		var license License
		if err := a.db.First(&license, *device.LicenseID).Error; err == nil {
			license.IsActive = false
			a.clearLicenseSession(&license)
			_ = a.db.Save(&license).Error
		}
	}
	if err := a.db.Save(device).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "machine_id": device.MachineID})
}

func (a *App) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	identity := r.URL.Query().Get("identity")
	user, err := a.getUserByIdentity(identity)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	subscription, _ := a.getActiveSubscription(user.ID)
	var currentPlan *SubscriptionPlan
	if subscription != nil {
		currentPlan, _ = a.getPlanByCode(subscription.PlanCode)
	}
	var devices []DeviceActivation
	_ = a.db.Where("user_id = ?", user.ID).Order("id desc").Find(&devices).Error
	deviceItems := make([]map[string]any, 0, len(devices))
	for _, item := range devices {
		deviceItems = append(deviceItems, map[string]any{"machine_id": item.MachineID, "device_name": item.DeviceName, "status": item.Status, "approved_at": item.ApprovedAt, "last_login_at": item.LastLoginAt, "license_id": item.LicenseID})
	}
	response := map[string]any{
		"user": map[string]any{"id": user.ID, "username": user.Username, "email": user.Email, "is_active": user.IsActive},
		"subscription": map[string]any{
			"plan_code":   nil,
			"plan_name":   nil,
			"status":      "inactive",
			"expires_at":  nil,
			"max_devices": 0,
			"plan":        nil,
		},
		"devices": deviceItems,
	}
	if subscription != nil {
		response["subscription"] = map[string]any{
			"plan_code":   subscription.PlanCode,
			"plan_name":   maybePlanName(currentPlan, subscription.PlanCode),
			"status":      subscription.Status,
			"expires_at":  subscription.ExpiresAt,
			"max_devices": subscription.MaxDevices,
			"plan":        maybeSerializedPlan(currentPlan),
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleResetHWID(w http.ResponseWriter, r *http.Request) {
	type resetReq struct {
		Key string `json:"key"`
	}
	var req resetReq
	if !decodeJSON(w, r, &req) {
		return
	}
	license, err := a.getLicenseByKey(req.Key)
	if err != nil {
		writeError(w, http.StatusNotFound, "License not found")
		return
	}
	license.MachineID = ""
	a.clearLicenseSession(license)
	if err := a.db.Save(license).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "message": "HWID Reset Complete"})
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	count := func(model any, query string, args ...any) int64 {
		var c int64
		db := a.db.Model(model)
		if query != "" {
			db = db.Where(query, args...)
		}
		_ = db.Count(&c).Error
		return c
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_licenses":       count(&License{}, ""),
		"active_sessions":      count(&License{}, "session_id <> ''"),
		"total_users":          count(&WebUser{}, ""),
		"total_devices":        count(&DeviceActivation{}, ""),
		"active_subscriptions": count(&CustomerSubscription{}, "status = ?", "active"),
		"total_plans":          count(&SubscriptionPlan{}, ""),
		"server_status":        "online",
	})
}

func (a *App) handleRuntimeWorkers(w http.ResponseWriter, r *http.Request) {
	a.runtimeMonitor.mu.Lock()
	defer a.runtimeMonitor.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":              "go-single-process",
		"available_workers": 1,
		"idle_workers":      ternaryInt(a.runtimeMonitor.ActiveRequests == 0, 1, 0),
		"busy_workers":      ternaryInt(a.runtimeMonitor.ActiveRequests > 0, 1, 0),
		"inflight_requests": a.runtimeMonitor.ActiveRequests,
		"handled_requests":  a.runtimeMonitor.Handled,
		"uptime_seconds":    int(time.Since(a.runtimeMonitor.StartTime).Seconds()),
		"pid":               os.Getpid(),
	})
}

func (a *App) handleRuntimeWorkersScale(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusConflict, "Runtime scaling is not supported in single-process Go mode")
}

func (a *App) handleUploadModule(w http.ResponseWriter, r *http.Request) {
	var req ModuleUploadRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var sidecarResp sidecarEncryptModuleResp
	if err := a.callSidecar("/encrypt-module", map[string]any{"code_content": req.CodeContent}, &sidecarResp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	module := ModuleVersion{Name: req.Name, Version: req.Version, EncryptedCode: sidecarResp.EncryptedCode, HashChecksum: sidecarResp.Checksum}
	if err := a.db.Create(&module).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "Uploaded", "module": req.Name, "hash_checksum": sidecarResp.Checksum})
}

// Helpers
type HTTPError struct {
	StatusCode int
	Detail     string
}

func (e *HTTPError) Error() string { return e.Detail }

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"detail": detail})
}

func writeHTTPError(w http.ResponseWriter, err error) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		writeError(w, httpErr.StatusCode, httpErr.Detail)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return false
	}
	return true
}

func normalizeIdentity(value string) string  { return strings.ToLower(strings.TrimSpace(value)) }
func normalizeMachineID(value string) string { return strings.TrimSpace(value) }

func hashAttemptValue(value string) string {
	value = normalizeIdentity(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}

func normalizeClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return strings.TrimSpace(host)
}

func (a *App) buildAuthScopeKeys(machineID string, r *http.Request, identity string, accessKey string) []string {
	scopes := []string{}
	if machineID = normalizeMachineID(machineID); machineID != "" {
		scopes = append(scopes, "machine:"+machineID)
	}
	if ip := normalizeClientIP(r); ip != "" {
		scopes = append(scopes, "ip:"+ip)
	}
	if h := hashAttemptValue(identity); h != "" {
		scopes = append(scopes, "identity:"+h)
	}
	if h := hashAttemptValue(accessKey); h != "" {
		scopes = append(scopes, "access:"+h)
	}
	return uniqueStrings(scopes)
}

func (a *App) getAuthLock(scopes []string) *time.Time {
	var locked *time.Time
	for _, scope := range scopes {
		if value := a.verifyGuard.Check(scope); value != nil {
			if locked == nil || value.After(*locked) {
				locked = value
			}
		}
	}
	return locked
}

func (a *App) clearAuthFailures(scopes []string) {
	for _, scope := range scopes {
		a.verifyGuard.Clear(scope)
	}
}

func (a *App) registerAuthFailure(scopes []string, detail string, statusCode int) {
	var locked *time.Time
	for _, scope := range scopes {
		if value := a.verifyGuard.RegisterFailure(scope); value != nil {
			if locked == nil || value.After(*locked) {
				locked = value
			}
		}
	}
	if locked != nil {
	}
}

func hashDeviceBinding(deviceBinding string) string {
	value := strings.TrimSpace(deviceBinding)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (a *App) allowDevSourceBuild(r *http.Request) bool {
	if a.cfg.DevMode || a.cfg.AllowInsecureDefaults {
		return true
	}
	clientIP := normalizeClientIP(r)
	return clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost"
}

func (a *App) verifyBuildAttestation(buildID string, attestation map[string]any, r *http.Request) (string, string, error) {
	normalized := strings.TrimSpace(buildID)
	if normalized == "" {
		normalized = "DEV-SOURCE"
	}
	if normalized == "DEV-SOURCE" {
		if !a.allowDevSourceBuild(r) {
			return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "DEV-SOURCE build chi duoc phep tren local/dev backend. Build production phai co release manifest hop le."}
		}
		return normalized, "dev-source", nil
	}
	if len(attestation) == 0 {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Missing release manifest attestation for production build"}
	}
	payload := map[string]any{}
	for key, value := range attestation {
		payload[key] = value
	}
	signature := fallbackString(toString(payload["signature"]), "")
	delete(payload, "signature")
	if fallbackString(toString(payload["signature_algorithm"]), "") != "ed25519" {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Release manifest algorithm invalid"}
	}
	if fallbackString(toString(payload["build_nonce"]), "") != normalized {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Release manifest build id mismatch"}
	}
	pubRaw, err := base64.StdEncoding.DecodeString(a.cfg.ReleasePublicKeyB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return "", "", &HTTPError{StatusCode: http.StatusServiceUnavailable, Detail: "Release manifest public key is not configured"}
	}
	sigRaw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Release manifest signature invalid"}
	}
	message, err := canonicalJSON(payload)
	if err != nil {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Release manifest signature invalid"}
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(message), sigRaw) {
		return "", "", &HTTPError{StatusCode: http.StatusForbidden, Detail: "Release manifest signature invalid"}
	}
	fingerprint := sha256HexString(message + "|" + signature)
	return normalized, fingerprint, nil
}

func (a *App) issueSessionForLicense(licenseItem *License, buildID string, accountContext map[string]any) (map[string]any, error) {
	sessionID := uuid.NewString()
	sessionKey, err := generateFernetKey()
	if err != nil {
		return nil, err
	}
	expiration := time.Now().UTC().Add(sessionLifetimeMinutes * time.Minute)
	licenseItem.SessionID = sessionID
	licenseItem.SessionKey = sessionKey
	licenseItem.SessionExpiration = &expiration
	if err := a.db.Save(licenseItem).Error; err != nil {
		return nil, err
	}
	challenge := a.sessionGuard.Bootstrap(sessionID, expiration, fallbackString(buildID, "DEV-SOURCE"))
	return buildSessionResponse(licenseItem, challenge, accountContext), nil
}

func buildSessionResponse(licenseItem *License, challenge map[string]any, accountContext map[string]any) map[string]any {
	if challenge == nil {
		challenge = map[string]any{}
	}
	response := map[string]any{
		"valid":                  true,
		"message":                "Authorized",
		"license_expiration":     licenseItem.ExpirationDate,
		"expiration":             licenseItem.ExpirationDate,
		"machine_id_bound":       licenseItem.MachineID,
		"session_id":             licenseItem.SessionID,
		"session_key":            licenseItem.SessionKey,
		"session_expiration":     licenseItem.SessionExpiration,
		"build_id":               fallbackString(toString(challenge["build_id"]), "DEV-SOURCE"),
		"sync_token":             fallbackString(toString(challenge["sync_token"]), ""),
		"sync_token_ttl_seconds": getInt(challenge["token_ttl_seconds"], syncTokenTTLSeconds),
		"rotation_after_seconds": getInt(challenge["rotation_after_seconds"], rotationMaxSeconds),
		"session_epoch":          getInt(challenge["epoch"], 1),
		"access_key":             licenseItem.Key,
		"plan_code":              licenseItem.PlanCode,
		"auth_source":            fallbackString(licenseItem.Source, "legacy"),
	}
	for key, value := range accountContext {
		response[key] = value
	}
	return response
}

func (a *App) getLicenseByKey(key string) (*License, error) {
	var license License
	if err := a.db.Where("key = ? AND is_active = ?", strings.TrimSpace(key), true).First(&license).Error; err != nil {
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "License verification failed"}
	}
	return &license, nil
}

func (a *App) validateLicenseBinding(licenseItem *License, machineID string) error {
	now := time.Now().UTC()
	if strings.TrimSpace(licenseItem.MachineID) == "" {
		licenseItem.MachineID = machineID
		licenseItem.ActivatedAt = &now
		expiration := now.Add(time.Duration(maxInt(licenseItem.DurationDays, 30)) * 24 * time.Hour)
		licenseItem.ExpirationDate = &expiration
		if err := a.db.Save(licenseItem).Error; err != nil {
			return err
		}
	} else if licenseItem.MachineID != machineID {
		return &HTTPError{StatusCode: http.StatusForbidden, Detail: "License verification failed"}
	}
	if licenseItem.ExpirationDate != nil && now.After(licenseItem.ExpirationDate.UTC()) {
		return &HTTPError{StatusCode: http.StatusForbidden, Detail: "License expired"}
	}
	return nil
}

func (a *App) getUserByIdentity(identity string) (*WebUser, error) {
	normalized := normalizeIdentity(identity)
	if normalized == "" {
		return nil, nil
	}
	var user WebUser
	if err := a.db.Where("username = ? OR email = ?", normalized, normalized).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (a *App) getPlanByCode(code string) (*SubscriptionPlan, error) {
	var plan SubscriptionPlan
	if err := a.db.Where("code = ?", strings.ToLower(strings.TrimSpace(code))).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &plan, nil
}

func serializePlan(plan SubscriptionPlan) map[string]any {
	return map[string]any{
		"plan_code":          plan.Code,
		"name":               plan.Name,
		"duration_label":     plan.DurationLabel,
		"duration_days":      plan.DurationDays,
		"max_devices":        plan.MaxDevices,
		"is_active":          plan.IsActive,
		"is_trial":           plan.IsTrial,
		"sort_order":         plan.SortOrder,
		"price_amount":       plan.PriceAmount,
		"currency":           fallbackString(plan.Currency, "VND"),
		"price_note":         plan.PriceNote,
		"external_price_ref": plan.ExternalPriceRef,
	}
}

func (a *App) ensureDefaultPlans(overwriteExisting, overwritePrices bool) error {
	for _, definition := range defaultPlanCatalog {
		plan, err := a.getPlanByCode(definition.Code)
		if err != nil {
			return err
		}
		if plan == nil {
			copyValue := definition
			if err := a.db.Create(&copyValue).Error; err != nil {
				return err
			}
			continue
		}
		if overwriteExisting {
			plan.Name = definition.Name
			plan.DurationLabel = definition.DurationLabel
			plan.DurationDays = definition.DurationDays
			plan.MaxDevices = definition.MaxDevices
			plan.IsActive = definition.IsActive
			plan.IsTrial = definition.IsTrial
			plan.SortOrder = definition.SortOrder
			plan.PriceNote = definition.PriceNote
			plan.ExternalPriceRef = definition.ExternalPriceRef
			if overwritePrices {
				plan.PriceAmount = definition.PriceAmount
				plan.Currency = definition.Currency
			}
			if err := a.db.Save(plan).Error; err != nil {
				return err
			}
		} else if overwritePrices {
			plan.PriceAmount = definition.PriceAmount
			plan.Currency = definition.Currency
			if err := a.db.Save(plan).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) getActiveSubscription(userID uint) (*CustomerSubscription, error) {
	var subscription CustomerSubscription
	if err := a.db.Where("user_id = ? AND status = ?", userID, "active").Order("expires_at desc, id desc").First(&subscription).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if subscription.ExpiresAt != nil && !subscription.ExpiresAt.After(time.Now().UTC()) {
		subscription.Status = "expired"
		_ = a.db.Save(&subscription).Error
		return nil, nil
	}
	return &subscription, nil
}

func (a *App) getDeviceActivation(userID uint, machineID string) (*DeviceActivation, error) {
	var device DeviceActivation
	if err := a.db.Where("user_id = ? AND machine_id = ?", userID, machineID).Order("id desc").First(&device).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

func (a *App) enforceDeviceBinding(device *DeviceActivation, deviceBinding string) error {
	providedHash := hashDeviceBinding(deviceBinding)
	if providedHash == "" {
		return &HTTPError{StatusCode: http.StatusForbidden, Detail: "Phien ban EXE nay thieu device binding proof. Vui long dang nhap bang ban EXE moi nhat."}
	}
	if strings.TrimSpace(device.DeviceBindingHash) != "" {
		if !hmac.Equal([]byte(device.DeviceBindingHash), []byte(providedHash)) {
			return &HTTPError{StatusCode: http.StatusForbidden, Detail: "Device binding proof mismatch. Access nay khong the su dung tren may khac."}
		}
		return nil
	}
	now := time.Now().UTC()
	device.DeviceBindingHash = providedHash
	device.BindingUpdatedAt = &now
	return nil
}

func createAccessKey() string {
	token := strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))
	return fmt.Sprintf("ACC-%s-%s-%s-%s", token[:8], token[8:16], token[16:24], token[24:32])
}

func (a *App) ensureDeviceAccessLicense(user *WebUser, subscription *CustomerSubscription, device *DeviceActivation) (*License, error) {
	remainingDays := 30
	if subscription.ExpiresAt != nil {
		remainingDays = maxInt(1, int(subscription.ExpiresAt.Sub(time.Now().UTC()).Hours()/24)+1)
	}
	var license *License
	if device.LicenseID != nil {
		var item License
		if err := a.db.First(&item, *device.LicenseID).Error; err == nil {
			license = &item
		}
	}
	now := time.Now().UTC()
	if license == nil {
		item := &License{
			Key:             createAccessKey(),
			MachineID:       device.MachineID,
			AccountUsername: user.Username,
			PlanCode:        subscription.PlanCode,
			Source:          "account_portal",
			IsActive:        true,
			CreatedAt:       now,
			ActivatedAt:     fallbackTimePtr(device.ApprovedAt, now),
			ExpirationDate:  subscription.ExpiresAt,
			DurationDays:    remainingDays,
			Notes:           fmt.Sprintf("Auto-created for %s:%s", user.Username, device.MachineID),
		}
		if err := a.db.Create(item).Error; err != nil {
			return nil, err
		}
		device.LicenseID = &item.ID
		license = item
	} else {
		license.MachineID = device.MachineID
		license.AccountUsername = user.Username
		license.PlanCode = subscription.PlanCode
		license.Source = "account_portal"
		license.IsActive = true
		license.ExpirationDate = subscription.ExpiresAt
		license.DurationDays = remainingDays
		license.ActivatedAt = fallbackTimePtr(device.ApprovedAt, now)
		license.Notes = fmt.Sprintf("Synced for %s:%s", user.Username, device.MachineID)
	}
	if err := a.db.Save(license).Error; err != nil {
		return nil, err
	}
	if err := a.db.Save(device).Error; err != nil {
		return nil, err
	}
	return license, nil
}

func buildAccountContext(user WebUser, subscription CustomerSubscription, device DeviceActivation, plan *SubscriptionPlan) map[string]any {
	return map[string]any{
		"account_username":         user.Username,
		"account_email":            user.Email,
		"subscription_status":      subscription.Status,
		"subscription_expires_at":  subscription.ExpiresAt,
		"subscription_plan_code":   subscription.PlanCode,
		"subscription_plan_name":   maybePlanName(plan, subscription.PlanCode),
		"subscription_plan":        maybeSerializedPlan(plan),
		"subscription_max_devices": subscription.MaxDevices,
		"device_id":                device.MachineID,
		"device_name":              device.DeviceName,
	}
}

func (a *App) clearLicenseSession(licenseItem *License) {
	a.sessionGuard.Clear(licenseItem.SessionID)
	licenseItem.SessionID = ""
	licenseItem.SessionKey = ""
	licenseItem.SessionExpiration = nil
}

func (a *App) deactivateLicenseAccess(licenseItem *License, keepActive bool) error {
	a.clearLicenseSession(licenseItem)
	if !keepActive {
		licenseItem.IsActive = false
	}
	return a.db.Save(licenseItem).Error
}

func (a *App) buildAccountContextFromLicense(licenseItem *License, machineID, deviceName, deviceBinding string) (map[string]any, error) {
	if fallbackString(licenseItem.Source, "legacy") != "account_portal" {
		return nil, nil
	}
	identity := normalizeIdentity(licenseItem.AccountUsername)
	if identity == "" {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Account-bound access key is invalid"}
	}
	user, err := a.getUserByIdentity(identity)
	if err != nil || user == nil {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Account-bound access key is invalid"}
	}
	if !user.IsActive {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Account is disabled"}
	}
	subscription, err := a.getActiveSubscription(user.ID)
	if err != nil || subscription == nil {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: 402, Detail: "Tai khoan chua co goi su dung hoac goi da het han. Vui long mua goi tren website."}
	}
	device, err := a.getDeviceActivation(user.ID, machineID)
	if err != nil || device == nil || strings.ToLower(device.Status) != "active" {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Thiet bi nay chua duoc kich hoat cho tai khoan. Vui long vao website de dang ky machine ID."}
	}
	if err := a.enforceDeviceBinding(device, deviceBinding); err != nil {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, err
	}
	if device.LicenseID != nil && *device.LicenseID != licenseItem.ID {
		_ = a.deactivateLicenseAccess(licenseItem, false)
		return nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Access key hien tai khong con hop le cho thiet bi nay. Vui long dang nhap lai tren EXE."}
	}
	plan, _ := a.getPlanByCode(subscription.PlanCode)
	remainingDays := 30
	if subscription.ExpiresAt != nil {
		remainingDays = maxInt(1, int(subscription.ExpiresAt.Sub(time.Now().UTC()).Hours()/24)+1)
	}
	now := time.Now().UTC()
	licenseItem.MachineID = machineID
	licenseItem.AccountUsername = user.Username
	licenseItem.PlanCode = subscription.PlanCode
	licenseItem.Source = "account_portal"
	licenseItem.IsActive = true
	licenseItem.ExpirationDate = subscription.ExpiresAt
	licenseItem.DurationDays = remainingDays
	licenseItem.ActivatedAt = fallbackTimePtr(device.ApprovedAt, now)
	device.LicenseID = &licenseItem.ID
	device.LastLoginAt = &now
	if strings.TrimSpace(deviceName) != "" {
		device.DeviceName = strings.TrimSpace(deviceName)
	}
	if device.ApprovedAt == nil {
		device.ApprovedAt = &now
	}
	if err := a.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(licenseItem).Error; err != nil {
			return err
		}
		if err := tx.Save(device).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return buildAccountContext(*user, *subscription, *device, plan), nil
}

func (a *App) validateSessionRequest(req SessionAuthRequest, moduleName string, allowStale bool) (*License, map[string]any, error) {
	if !a.nonceCache.Consume(req.Nonce) {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Nonce already used"}
	}
	if math.Abs(float64(currentTimestamp()-req.Timestamp)) > 10 {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Timestamp out of sync"}
	}
	var license License
	if err := a.db.Where("session_id = ? AND is_active = ?", req.SessionID, true).First(&license).Error; err != nil || strings.TrimSpace(license.SessionKey) == "" {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Invalid session"}
	}
	if license.MachineID != req.MachineID {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Machine mismatch"}
	}
	if license.SessionExpiration == nil || time.Now().UTC().After(license.SessionExpiration.UTC()) {
		return nil, nil, &HTTPError{StatusCode: http.StatusUnauthorized, Detail: "Session expired"}
	}
	payload := map[string]any{
		"build_id":    req.BuildID,
		"session_id":  req.SessionID,
		"machine_id":  req.MachineID,
		"sync_token":  req.SyncToken,
		"module_name": moduleName,
		"nonce":       req.Nonce,
		"timestamp":   req.Timestamp,
	}
	if !hmac.Equal([]byte(signSessionPayload(license.SessionKey, payload)), []byte(req.Signature)) {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Invalid session signature"}
	}
	challenge := a.sessionGuard.Validate(req.SessionID, req.SyncToken, allowStale)
	if challenge == nil {
		return nil, nil, &HTTPError{StatusCode: http.StatusUnauthorized, Detail: "Session challenge expired"}
	}
	if fallbackString(toString(challenge["build_id"]), "DEV-SOURCE") != fallbackString(req.BuildID, "DEV-SOURCE") {
		return nil, nil, &HTTPError{StatusCode: http.StatusForbidden, Detail: "Build attestation mismatch"}
	}
	return &license, challenge, nil
}

func canonicalJSON(data map[string]any) (string, error) {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	buf := &bytes.Buffer{}
	buf.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := marshalJSONNoEscape(key)
		if err != nil {
			return "", err
		}
		valueJSON, err := marshalJSONNoEscape(data[key])
		if err != nil {
			return "", err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

func marshalJSONNoEscape(value any) ([]byte, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func signHMAC(secret string, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func signSessionPayload(sessionKey string, payload map[string]any) string {
	fields := map[string]any{
		"build_id":    fallbackString(toString(payload["build_id"]), ""),
		"machine_id":  fallbackString(toString(payload["machine_id"]), ""),
		"module_name": fallbackString(toString(payload["module_name"]), ""),
		"nonce":       fallbackString(toString(payload["nonce"]), ""),
		"session_id":  fallbackString(toString(payload["session_id"]), ""),
		"sync_token":  fallbackString(toString(payload["sync_token"]), ""),
		"timestamp":   getInt64(payload["timestamp"], 0),
	}
	message, _ := canonicalJSON(fields)
	return signHMAC(sessionKey, message)
}

func signServerResponse(sessionKey string, payload map[string]any) string {
	fields := map[string]any{
		"challenge":           fallbackString(toString(payload["challenge"]), ""),
		"checksum":            fallbackString(toString(payload["checksum"]), ""),
		"encrypted_code_hash": ternaryString(fallbackString(toString(payload["encrypted_code"]), "") != "", sha256HexString(fallbackString(toString(payload["encrypted_code"]), "")), ""),
		"fragment_seal":       fallbackString(toString(payload["fragment_seal"]), ""),
		"issued_at":           getInt64(payload["issued_at"], 0),
		"module_name":         fallbackString(toString(payload["module_name"]), ""),
		"response_type":       fallbackString(toString(payload["response_type"]), ""),
		"session_epoch":       getInt(payload["session_epoch"], 0),
		"session_id":          fallbackString(toString(payload["session_id"]), ""),
		"solution_hash":       sha256HexString(canonicalValue(payload["solution"])),
		"sync_token":          fallbackString(toString(payload["sync_token"]), ""),
		"type":                fallbackString(toString(payload["type"]), ""),
	}
	message, _ := canonicalJSON(fields)
	return signHMAC(sessionKey, message)
}

func currentTimestamp() int64             { return time.Now().UTC().Unix() }
func sha256Hex(data []byte) string        { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func sha256HexString(value string) string { return sha256Hex([]byte(value)) }

func generateFernetKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(raw), nil
}

func openDatabase(databaseURL string) (*gorm.DB, error) {
	if strings.HasPrefix(strings.ToLower(databaseURL), "sqlite:///") {
		sqlitePath := strings.TrimPrefix(databaseURL, "sqlite:///")
		if sqlitePath == "" {
			sqlitePath = filepath.Join(".", "Backend", "sql_app.db")
		}
		return gorm.Open(sqlite.Open(sqlitePath), &gorm.Config{})
	}
	if strings.HasPrefix(strings.ToLower(databaseURL), "sqlite://") {
		sqlitePath := strings.TrimPrefix(databaseURL, "sqlite://")
		if sqlitePath == "" {
			sqlitePath = filepath.Join(".", "Backend", "sql_app.db")
		}
		return gorm.Open(sqlite.Open(sqlitePath), &gorm.Config{})
	}
	return gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
}

func migrateDatabase(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return db.AutoMigrate(&License{}, &ModuleVersion{}, &WebUser{}, &SubscriptionPlan{}, &CustomerSubscription{}, &DeviceActivation{})
	}

	serverVersion, err := postgresServerVersionNum(db)
	if err != nil {
		return err
	}
	if serverVersion >= 90500 {
		return db.AutoMigrate(&License{}, &ModuleVersion{}, &WebUser{}, &SubscriptionPlan{}, &CustomerSubscription{}, &DeviceActivation{})
	}
	return migrateLegacyPostgres(db)
}

func postgresServerVersionNum(db *gorm.DB) (int, error) {
	var versionText string
	if err := db.Raw("SHOW server_version_num").Scan(&versionText).Error; err != nil {
		return 0, err
	}
	versionText = strings.TrimSpace(versionText)
	versionNum, err := strconv.Atoi(versionText)
	if err != nil {
		return 0, fmt.Errorf("parse server_version_num %q: %w", versionText, err)
	}
	return versionNum, nil
}

func migrateLegacyPostgres(db *gorm.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS licenses (
			id SERIAL PRIMARY KEY,
			key VARCHAR(128),
			machine_id VARCHAR(255),
			account_username VARCHAR(255),
			plan_code VARCHAR(255),
			source VARCHAR(64) DEFAULT 'legacy',
			notes TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ,
			activated_at TIMESTAMPTZ,
			expiration_date TIMESTAMPTZ,
			duration_days INTEGER DEFAULT 30,
			session_id VARCHAR(255),
			session_key VARCHAR(255),
			session_expiration TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS module_versions (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255),
			version VARCHAR(64),
			encrypted_code TEXT,
			hash_checksum VARCHAR(128),
			created_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS web_users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255),
			email VARCHAR(255),
			password_hash VARCHAR(512),
			full_name VARCHAR(255),
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ,
			notes TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS subscription_plans (
			id SERIAL PRIMARY KEY,
			code VARCHAR(255),
			name VARCHAR(255),
			duration_label VARCHAR(255),
			duration_days INTEGER DEFAULT 30,
			max_devices INTEGER DEFAULT 1,
			is_active BOOLEAN DEFAULT TRUE,
			is_trial BOOLEAN DEFAULT FALSE,
			sort_order INTEGER DEFAULT 100,
			price_amount INTEGER DEFAULT 0,
			currency VARCHAR(16) DEFAULT 'VND',
			price_note VARCHAR(255),
			external_price_ref VARCHAR(255),
			created_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS customer_subscriptions (
			id SERIAL PRIMARY KEY,
			user_id INTEGER,
			plan_code VARCHAR(255),
			status VARCHAR(64) DEFAULT 'active',
			starts_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ,
			max_devices INTEGER DEFAULT 1,
			purchase_ref VARCHAR(255),
			created_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ,
			notes TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS device_activations (
			id SERIAL PRIMARY KEY,
			user_id INTEGER,
			machine_id VARCHAR(255),
			device_name VARCHAR(255),
			device_binding_hash VARCHAR(255),
			status VARCHAR(64) DEFAULT 'pending',
			approved_at TIMESTAMPTZ,
			binding_updated_at TIMESTAMPTZ,
			last_login_at TIMESTAMPTZ,
			license_id INTEGER,
			created_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ,
			notes TEXT
		)`,
		legacyCreateIndexSQL("idx_licenses_key", "CREATE UNIQUE INDEX idx_licenses_key ON licenses (key)"),
		legacyCreateIndexSQL("idx_licenses_machine_id", "CREATE INDEX idx_licenses_machine_id ON licenses (machine_id)"),
		legacyCreateIndexSQL("idx_licenses_account_username", "CREATE INDEX idx_licenses_account_username ON licenses (account_username)"),
		legacyCreateIndexSQL("idx_licenses_session_id", "CREATE INDEX idx_licenses_session_id ON licenses (session_id)"),
		legacyCreateIndexSQL("idx_module_versions_name", "CREATE INDEX idx_module_versions_name ON module_versions (name)"),
		legacyCreateIndexSQL("idx_web_users_username", "CREATE UNIQUE INDEX idx_web_users_username ON web_users (username)"),
		legacyCreateIndexSQL("idx_web_users_email", "CREATE UNIQUE INDEX idx_web_users_email ON web_users (email)"),
		legacyCreateIndexSQL("idx_subscription_plans_code", "CREATE UNIQUE INDEX idx_subscription_plans_code ON subscription_plans (code)"),
		legacyCreateIndexSQL("idx_customer_subscriptions_user_id", "CREATE INDEX idx_customer_subscriptions_user_id ON customer_subscriptions (user_id)"),
		legacyCreateIndexSQL("idx_customer_subscriptions_plan_code", "CREATE INDEX idx_customer_subscriptions_plan_code ON customer_subscriptions (plan_code)"),
		legacyCreateIndexSQL("idx_customer_subscriptions_status", "CREATE INDEX idx_customer_subscriptions_status ON customer_subscriptions (status)"),
		legacyCreateIndexSQL("idx_customer_subscriptions_expires_at", "CREATE INDEX idx_customer_subscriptions_expires_at ON customer_subscriptions (expires_at)"),
		legacyCreateIndexSQL("idx_device_activations_user_id", "CREATE INDEX idx_device_activations_user_id ON device_activations (user_id)"),
		legacyCreateIndexSQL("idx_device_activations_machine_id", "CREATE INDEX idx_device_activations_machine_id ON device_activations (machine_id)"),
		legacyCreateIndexSQL("idx_device_activations_status", "CREATE INDEX idx_device_activations_status ON device_activations (status)"),
		legacyCreateIndexSQL("idx_device_activations_license_id", "CREATE INDEX idx_device_activations_license_id ON device_activations (license_id)"),
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}

func legacyCreateIndexSQL(indexName, createSQL string) string {
	safeName := strings.ReplaceAll(indexName, "'", "''")
	safeSQL := strings.ReplaceAll(createSQL, "'", "''")
	return fmt.Sprintf(
		"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relkind = 'i' AND relname = '%s') THEN EXECUTE '%s'; END IF; END $$;",
		safeName,
		safeSQL,
	)
}

func sha256HexForInternalBody(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return sha256HexString("")
	}
	if trimmed[0] == '{' {
		var data map[string]any
		if err := json.Unmarshal(trimmed, &data); err == nil {
			if canonical, err := canonicalJSON(data); err == nil {
				return sha256HexString(canonical)
			}
		}
	}
	if trimmed[0] == '[' {
		var data any
		if err := json.Unmarshal(trimmed, &data); err == nil {
			raw, err := json.Marshal(data)
			if err == nil {
				return sha256Hex(raw)
			}
		}
	}
	return sha256Hex(trimmed)
}

func (a *App) callSidecar(path string, payload any, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(a.cfg.SidecarURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sidecar error: %s", strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, target)
}

func (a *App) sidecarHashPassword(password string) (string, error) {
	var resp sidecarPasswordHashResp
	if err := a.callSidecar("/hash-password", map[string]any{"password": password}, &resp); err != nil {
		return "", err
	}
	return resp.PasswordHash, nil
}

func (a *App) sidecarVerifyPassword(password, passwordHash string) (bool, error) {
	var resp sidecarPasswordVerifyResp
	if err := a.callSidecar("/verify-password", map[string]any{"password": password, "password_hash": passwordHash}, &resp); err != nil {
		return false, err
	}
	return resp.Valid, nil
}

func parseOptionalTime(value string) (*time.Time, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, nil
	}
	if strings.HasSuffix(raw, "Z") {
		raw = strings.TrimSuffix(raw, "Z") + "+00:00"
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	utc := parsed.UTC()
	return &utc, nil
}

func fallbackString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func fallbackTimePtr(value *time.Time, fallback time.Time) *time.Time {
	if value != nil {
		return value
	}
	copyValue := fallback
	return &copyValue
}

func maybePlanName(plan *SubscriptionPlan, fallback string) string {
	if plan == nil {
		return fallback
	}
	return plan.Name
}

func maybeSerializedPlan(plan *SubscriptionPlan) any {
	if plan == nil {
		return nil
	}
	return serializePlan(*plan)
}

func maxInt(value, fallback int) int {
	if value < fallback {
		return fallback
	}
	return value
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok || strings.TrimSpace(item) == "" {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func toString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", value)
	}
}

func getInt(value any, fallback int) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return fallback
	}
}

func getInt64(value any, fallback int64) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return fallback
	}
}

func ternary(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func ternaryInt(condition bool, whenTrue, whenFalse int) int {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func ternaryString(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func canonicalValue(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case map[string]any:
		raw, _ := canonicalJSON(typed)
		return raw
	case []any, []string, []int:
		raw, _ := json.Marshal(typed)
		return string(raw)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

type bigHash struct{ value string }

func (b *bigHash) fromHex(value string) *bigHash {
	b.value = value
	return b
}

func (b *bigHash) String() string {
	if b == nil {
		return ""
	}
	return b.value
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}
