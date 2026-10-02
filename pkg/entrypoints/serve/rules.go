package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
)

// RulesAPIPath is where the resigning rules API is served.
const RulesAPIPath = "/_sigman/rules"

// maxRuleRequestSize bounds rule creation requests.
const maxRuleRequestSize = 64 << 10

// PushSigner signs paths as they are pushed.
type PushSigner interface {
	// SignPushed adds signatures to a narinfo pushed by owner, reporting whether any
	// were added.
	SignPushed(ctx context.Context, owner string, ninfo *nixtypes.NarInfo) (bool, error)
}

// RuleManager serves the resigning rules API and applies the rules to pushed paths.
// Rules only apply to their owner's pushes, so a user can't get another user's
// uploads signed with keys that user isn't allowed to use.
type RuleManager struct {
	logger      *zap.Logger
	store       *resigning.RuleStore
	acl         *RuleACL
	privateKeys map[string]nixtypes.NamedPrivateKey
	publicKeys  map[string]nixtypes.NamedPublicKey
	maxTTL      time.Duration
	now         func() time.Time
}

// NewRuleManager creates a rule manager. maxTTL limits how long rules may last (0 for
// no limit).
func NewRuleManager(l *zap.Logger, store *resigning.RuleStore, acl *RuleACL,
	privateKeys []nixtypes.NamedPrivateKey, publicKeys []nixtypes.NamedPublicKey, maxTTL time.Duration) *RuleManager {
	m := &RuleManager{
		logger:      l,
		store:       store,
		acl:         acl,
		privateKeys: map[string]nixtypes.NamedPrivateKey{},
		publicKeys:  map[string]nixtypes.NamedPublicKey{},
		maxTTL:      maxTTL,
		now:         time.Now,
	}
	for _, key := range privateKeys {
		m.privateKeys[key.KeyName] = key
		// Conditions can check for signatures by our own keys too.
		m.publicKeys[key.KeyName] = key.PublicKey()
	}
	for _, key := range publicKeys {
		m.publicKeys[key.KeyName] = key
	}
	return m
}

// SetClock overrides the time source, for testing expiry.
func (m *RuleManager) SetClock(now func() time.Time) {
	m.now = now
	m.store.SetClock(now)
}

func (m *RuleManager) SignPushed(ctx context.Context, owner string, ninfo *nixtypes.NarInfo) (bool, error) {
	if owner == "" {
		return false, nil
	}
	rules, err := m.store.List(resigning.RuleFilter{Owner: owner})
	if err != nil || len(rules) == 0 {
		return false, err
	}
	// Grants may have been revoked since the rule was created.
	access, err := m.acl.Access(ctx, owner)
	if err != nil {
		return false, err
	}
	l := m.logger.With(zap.String("store_path", ninfo.StorePath), zap.String("owner", owner))
	signed := false
	for _, rule := range rules {
		if !rule.Condition.Matches(ninfo, m.publicKeys) {
			continue
		}
		for _, keyName := range rule.SignWith {
			key, loaded := m.privateKeys[keyName]
			if !access.Keys[keyName] || !loaded {
				l.Warn("Rule key is no longer available to its owner", zap.String("rule", rule.ID),
					zap.String("key", keyName))
				continue
			}
			didSign, _, err := ninfo.Sign(key)
			if err != nil {
				return signed, err
			}
			if didSign {
				l.Info("Signed pushed path by rule", zap.String("rule", rule.ID), zap.String("key", keyName))
			}
			signed = signed || didSign
		}
	}
	return signed, nil
}

// createRuleRequest is the body of a rule creation request.
type createRuleRequest struct {
	Description string               `json:"description"`
	Condition   *resigning.Condition `json:"condition"`
	SignWith    []string             `json:"sign_with"`
	// ExpiresIn is a duration (e.g. "2h") after which the rule stops applying.
	ExpiresIn string `json:"expires_in"`
	// ExpiresAt is the time the rule stops applying.
	ExpiresAt *time.Time `json:"expires_at"`
}

type listRulesResponse struct {
	Rules []resigning.Rule `json:"rules"`
}

type deleteRulesResponse struct {
	Deleted int              `json:"deleted"`
	Rules   []resigning.Rule `json:"rules"`
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, apiError{Error: fmt.Sprintf(format, args...)})
}

func (m *RuleManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := httpauth.IdentityFromContext(r.Context())
	if !ok || id.Username == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	access, err := m.acl.Access(r.Context(), id.Username)
	if err != nil {
		m.logger.Error("Could not determine rule access", zap.String("username", id.Username), zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "could not determine access")
		return
	}
	if !access.CanManageRules() {
		writeError(w, http.StatusForbidden, "not allowed to manage resigning rules")
		return
	}

	ruleID := strings.Trim(strings.TrimPrefix(r.URL.Path, RulesAPIPath), "/")
	switch {
	case ruleID == "" && r.Method == http.MethodGet:
		m.listRules(w, r, id.Username, access)
	case ruleID == "" && r.Method == http.MethodPost:
		m.createRule(w, r, id.Username, access)
	case ruleID == "" && r.Method == http.MethodDelete:
		m.deleteRules(w, r, id.Username, access)
	case ruleID != "" && !strings.Contains(ruleID, "/") && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		m.ruleByID(w, r, ruleID, id.Username, access)
	default:
		w.Header().Set("Allow", lo.Ternary(ruleID == "", "GET, POST, DELETE", "GET, DELETE"))
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// filterFor builds a rule filter from query parameters. Users who aren't admins only
// ever see their own rules.
func filterFor(r *http.Request, username string, access Access) (resigning.RuleFilter, error) {
	filter := resigning.RuleFilter{
		Owner:    r.URL.Query().Get("owner"),
		SignWith: r.URL.Query().Get("sign_with"),
	}
	if !access.Admin {
		if filter.Owner != "" && filter.Owner != username {
			return filter, errors.New("only admins may manage other users' rules")
		}
		filter.Owner = username
	}
	return filter, nil
}

func (m *RuleManager) listRules(w http.ResponseWriter, r *http.Request, username string, access Access) {
	filter, err := filterFor(r, username, access)
	if err != nil {
		writeError(w, http.StatusForbidden, "%v", err)
		return
	}
	rules, err := m.store.List(filter)
	if err != nil {
		m.logger.Error("Could not list rules", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "could not list rules")
		return
	}
	writeJSON(w, http.StatusOK, listRulesResponse{Rules: rules})
}

func (m *RuleManager) createRule(w http.ResponseWriter, r *http.Request, username string, access Access) {
	var req createRuleRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRuleRequestSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule: %v", err)
		return
	}

	now := m.now()
	rule := resigning.Rule{
		ID:          resigning.NewRuleID(),
		Owner:       username,
		Description: req.Description,
		Condition:   req.Condition,
		SignWith:    req.SignWith,
		Created:     now,
	}
	if err := rule.Validate(m.privateKeys, m.publicKeys); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule: %v", err)
		return
	}
	for _, key := range rule.SignWith {
		if !access.Keys[key] {
			writeError(w, http.StatusForbidden, "not allowed to sign with key %s", key)
			return
		}
	}

	switch {
	case req.ExpiresIn != "" && req.ExpiresAt != nil:
		writeError(w, http.StatusBadRequest, "only one of expires_in and expires_at may be set")
		return
	case req.ExpiresIn != "":
		ttl, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || ttl <= 0 {
			writeError(w, http.StatusBadRequest, "expires_in must be a positive duration")
			return
		}
		expires := now.Add(ttl)
		rule.Expires = &expires
	case req.ExpiresAt != nil:
		rule.Expires = req.ExpiresAt
	case m.maxTTL > 0:
		expires := now.Add(m.maxTTL)
		rule.Expires = &expires
	}
	if rule.Expires != nil && !rule.Expires.After(now) {
		writeError(w, http.StatusBadRequest, "rule expiry must be in the future")
		return
	}
	if m.maxTTL > 0 && rule.Expires.Sub(now) > m.maxTTL {
		writeError(w, http.StatusBadRequest, "rules may not last longer than %s", m.maxTTL)
		return
	}

	if err := m.store.Create(&rule); err != nil {
		m.logger.Error("Could not create rule", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "could not create rule")
		return
	}
	m.logger.Info("Created resigning rule", zap.String("rule", rule.ID), zap.String("owner", username),
		zap.Strings("sign_with", rule.SignWith))
	w.Header().Set("Location", RulesAPIPath+"/"+rule.ID)
	writeJSON(w, http.StatusCreated, rule)
}

func (m *RuleManager) ruleByID(w http.ResponseWriter, r *http.Request, ruleID string, username string, access Access) {
	rule, err := m.store.Get(ruleID)
	if err != nil {
		m.logger.Error("Could not get rule", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "could not get rule")
		return
	}
	// Other users' rules are reported as missing, so rule IDs can't be probed.
	if rule == nil || (!access.Admin && rule.Owner != username) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, rule)
		return
	}
	deleted, err := m.store.Delete(resigning.RuleFilter{ID: rule.ID})
	if err != nil {
		m.logger.Error("Could not delete rule", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "could not delete rule")
		return
	}
	m.logger.Info("Deleted resigning rule", zap.String("rule", rule.ID), zap.String("by", username))
	writeJSON(w, http.StatusOK, deleteRulesResponse{Deleted: len(deleted), Rules: deleted})
}

func (m *RuleManager) deleteRules(w http.ResponseWriter, r *http.Request, username string, access Access) {
	filter, err := filterFor(r, username, access)
	if err != nil {
		writeError(w, http.StatusForbidden, "%v", err)
		return
	}
	// Guard admins against deleting every rule by accident.
	if access.Admin && filter.Owner == "" && filter.SignWith == "" && r.URL.Query().Get("all") != "true" {
		writeError(w, http.StatusBadRequest, "give owner or sign_with, or all=true to delete every rule")
		return
	}
	deleted, err := m.store.Delete(filter)
	if err != nil {
		m.logger.Error("Could not delete rules", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "could not delete rules")
		return
	}
	m.logger.Info("Deleted resigning rules", zap.Int("count", len(deleted)), zap.String("by", username),
		zap.String("owner", filter.Owner), zap.String("sign_with", filter.SignWith))
	writeJSON(w, http.StatusOK, deleteRulesResponse{Deleted: len(deleted), Rules: deleted})
}
