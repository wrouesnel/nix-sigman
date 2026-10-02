package resigning

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
)

// Condition selects the narinfos a Rule applies to. Keys are referred to by name so
// conditions can be stored and sent over the API. Exactly one operand must be set.
type Condition struct {
	And []*Condition `json:"and,omitempty" yaml:"and,omitempty"`
	Or  []*Condition `json:"or,omitempty" yaml:"or,omitempty"`
	Not *Condition   `json:"not,omitempty" yaml:"not,omitempty"`
	// Signed matches narinfos with (true) or without (false) any signatures.
	Signed *bool `json:"signed,omitempty" yaml:"signed,omitempty"`
	// SignedBy matches narinfos with a valid signature from the named public key.
	SignedBy string `json:"signed_by,omitempty" yaml:"signed_by,omitempty"`
	// Name is a glob matched against the store path name without its hash
	// (e.g. "hello-*" matches /nix/store/<hash>-hello-2.12).
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// Validate checks the condition is well-formed and only refers to known public keys.
func (c *Condition) Validate(publicKeys map[string]nixtypes.NamedPublicKey) error {
	if c == nil {
		return errors.New("empty condition")
	}
	operands := lo.Count([]bool{c.And != nil, c.Or != nil, c.Not != nil, c.Signed != nil,
		c.SignedBy != "", c.Name != ""}, true)
	if operands != 1 {
		return fmt.Errorf("a condition must have exactly one operand, got %d", operands)
	}
	switch {
	case c.And != nil || c.Or != nil:
		children := slices.Concat(c.And, c.Or)
		if len(children) == 0 {
			return errors.New("and/or need at least one condition")
		}
		for _, child := range children {
			if err := child.Validate(publicKeys); err != nil {
				return err
			}
		}
	case c.Not != nil:
		return c.Not.Validate(publicKeys)
	case c.SignedBy != "":
		if _, found := publicKeys[c.SignedBy]; !found {
			return fmt.Errorf("public key not loaded: %s", c.SignedBy)
		}
	case c.Name != "":
		if _, err := path.Match(c.Name, ""); err != nil {
			return fmt.Errorf("invalid name pattern %q: %w", c.Name, err)
		}
	}
	return nil
}

// Matches evaluates the condition. A nil condition matches everything.
func (c *Condition) Matches(ninfo *nixtypes.NarInfo, publicKeys map[string]nixtypes.NamedPublicKey) bool {
	switch {
	case c == nil:
		return true
	case c.And != nil:
		return lo.EveryBy(c.And, func(child *Condition) bool { return child.Matches(ninfo, publicKeys) })
	case c.Or != nil:
		return lo.SomeBy(c.Or, func(child *Condition) bool { return child.Matches(ninfo, publicKeys) })
	case c.Not != nil:
		return !c.Not.Matches(ninfo, publicKeys)
	case c.Signed != nil:
		return (len(ninfo.Sig) > 0) == *c.Signed
	case c.SignedBy != "":
		key, found := publicKeys[c.SignedBy]
		if !found {
			return false
		}
		valid, _ := ninfo.Verify(key)
		return valid
	case c.Name != "":
		_, name, _ := strings.Cut(filepath.Base(ninfo.StorePath), "-")
		matched, _ := path.Match(c.Name, name)
		return matched
	}
	return false
}

// Rule signs narinfos matching Condition with the SignWith private keys. Rules are
// created at runtime by users, and only apply to paths their Owner pushes.
type Rule struct {
	ID          string     `json:"id"`
	Owner       string     `json:"owner"`
	Description string     `json:"description,omitempty"`
	Condition   *Condition `json:"condition,omitempty"`
	SignWith    []string   `json:"sign_with"`
	Created     time.Time  `json:"created"`
	Expires     *time.Time `json:"expires,omitempty"`
}

// Active reports whether the rule hasn't expired at now.
func (r *Rule) Active(now time.Time) bool {
	return r.Expires == nil || now.Before(*r.Expires)
}

// Validate checks the rule refers only to loaded keys.
func (r *Rule) Validate(privateKeys map[string]nixtypes.NamedPrivateKey, publicKeys map[string]nixtypes.NamedPublicKey) error {
	if len(r.SignWith) == 0 {
		return errors.New("sign_with must name at least one private key")
	}
	for _, key := range r.SignWith {
		if _, found := privateKeys[key]; !found {
			return fmt.Errorf("private key not loaded: %s", key)
		}
	}
	if r.Condition != nil {
		if err := r.Condition.Validate(publicKeys); err != nil {
			return fmt.Errorf("invalid condition: %w", err)
		}
	}
	return nil
}

// NewRuleID returns a random rule identifier.
func NewRuleID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}
