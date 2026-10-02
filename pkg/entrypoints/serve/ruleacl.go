package serve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v4"
)

// GroupChecker checks directory group membership.
type GroupChecker interface {
	IsMemberOfAny(ctx context.Context, username string, groupDNs []string) (bool, error)
}

// ACLSubjects selects users by username glob or LDAP group.
type ACLSubjects struct {
	// Users are glob patterns matched against the authenticated username (Kerberos
	// users are principal@REALM).
	Users []string `yaml:"users"`
	// LDAPGroups are group DNs. Kerberos principals are looked up by primary name.
	LDAPGroups []string `yaml:"ldap_groups"`
}

// ACLGrant allows subjects to create rules signing with the named private keys.
type ACLGrant struct {
	ACLSubjects `yaml:",inline"`
	// Keys are private key names, or glob patterns of them.
	Keys []string `yaml:"keys"`
}

// RuleACLFile is the format of the rule access control file.
type RuleACLFile struct {
	// Admins may list and delete every user's rules.
	Admins ACLSubjects `yaml:"admins"`
	Grants []ACLGrant  `yaml:"grants"`
}

// Access is what a user may do with resigning rules.
type Access struct {
	Admin bool
	// Keys are the private key names the user may sign with.
	Keys map[string]bool
}

// CanManageRules reports whether the user may use the rules API at all.
func (a Access) CanManageRules() bool {
	return a.Admin || len(a.Keys) > 0
}

type accessEntry struct {
	access  Access
	expires time.Time
}

// RuleACL decides which users may manage rules and sign with which keys.
type RuleACL struct {
	file     RuleACLFile
	keyNames []string
	groups   GroupChecker
	cacheTTL time.Duration

	mtx   sync.Mutex
	cache map[string]accessEntry
}

// LoadRuleACL loads the ACL file. keyNames are the loaded private keys. groups may be
// nil if LDAP isn't configured, in which case the file can't use LDAP groups.
func LoadRuleACL(filename string, keyNames []string, groups GroupChecker, cacheTTL time.Duration) (*RuleACL, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var file RuleACLFile
	if err := yaml.Load(content, &file, yaml.WithKnownFields()); err != nil {
		return nil, fmt.Errorf("could not parse rule ACL %s: %w", filename, err)
	}
	return NewRuleACL(file, keyNames, groups, cacheTTL)
}

// NewRuleACL validates an ACL.
func NewRuleACL(file RuleACLFile, keyNames []string, groups GroupChecker, cacheTTL time.Duration) (*RuleACL, error) {
	var errs []error
	checkSubjects := func(what string, s ACLSubjects) {
		for _, pattern := range s.Users {
			if _, err := path.Match(pattern, ""); err != nil {
				errs = append(errs, fmt.Errorf("%s: invalid user pattern %q", what, pattern))
			}
		}
		if len(s.LDAPGroups) > 0 && groups == nil {
			errs = append(errs, fmt.Errorf("%s: ldap_groups requires LDAP to be configured", what))
		}
	}
	checkSubjects("admins", file.Admins)
	for i, grant := range file.Grants {
		what := fmt.Sprintf("grant %d", i+1)
		checkSubjects(what, grant.ACLSubjects)
		if len(grant.Keys) == 0 {
			errs = append(errs, fmt.Errorf("%s: no keys", what))
		}
		for _, pattern := range grant.Keys {
			matched := false
			for _, name := range keyNames {
				ok, err := path.Match(pattern, name)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: invalid key pattern %q", what, pattern))
					break
				}
				matched = matched || ok
			}
			if !matched {
				errs = append(errs, fmt.Errorf("%s: no loaded private key matches %q", what, pattern))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &RuleACL{
		file:     file,
		keyNames: keyNames,
		groups:   groups,
		cacheTTL: cacheTTL,
		cache:    map[string]accessEntry{},
	}, nil
}

// directoryName is the name to look a user up in LDAP by: Kerberos principals are
// reduced to their primary name.
func directoryName(username string) string {
	name, _, _ := strings.Cut(username, "@")
	name, _, _ = strings.Cut(name, "/")
	return name
}

func (a *RuleACL) matches(ctx context.Context, s ACLSubjects, username string) (bool, error) {
	for _, pattern := range s.Users {
		if ok, _ := path.Match(pattern, username); ok {
			return true, nil
		}
	}
	if len(s.LDAPGroups) > 0 && a.groups != nil {
		return a.groups.IsMemberOfAny(ctx, directoryName(username), s.LDAPGroups)
	}
	return false, nil
}

// Access returns what the user may do. Results are cached, since group lookups are
// expensive and pushes check access for every path.
func (a *RuleACL) Access(ctx context.Context, username string) (Access, error) {
	now := time.Now()
	a.mtx.Lock()
	entry, found := a.cache[username]
	a.mtx.Unlock()
	if found && now.Before(entry.expires) {
		return entry.access, nil
	}

	access := Access{Keys: map[string]bool{}}
	var err error
	if access.Admin, err = a.matches(ctx, a.file.Admins, username); err != nil {
		return Access{}, err
	}
	for _, grant := range a.file.Grants {
		ok, err := a.matches(ctx, grant.ACLSubjects, username)
		if err != nil {
			return Access{}, err
		}
		if !ok {
			continue
		}
		for _, pattern := range grant.Keys {
			for _, name := range a.keyNames {
				if matched, _ := path.Match(pattern, name); matched {
					access.Keys[name] = true
				}
			}
		}
	}

	if a.cacheTTL > 0 {
		a.mtx.Lock()
		for k, e := range a.cache {
			if now.After(e.expires) {
				delete(a.cache, k)
			}
		}
		a.cache[username] = accessEntry{access: access, expires: now.Add(a.cacheTTL)}
		a.mtx.Unlock()
	}
	return access, nil
}
