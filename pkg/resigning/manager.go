package resigning

import (
	"time"

	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
)

// ResigningRuleOption implements option types for configuring resigning rules
type ResigningRuleOption func(o *resigningRuleOpts) *resigningRuleOpts

type resigningRuleOpts struct {
	// NotBefore if set then this resigning rule will only activate after this time
	NotBefore *time.Time
	// NotAfter if set then this resigning rule expires after this time.
	NotAfter *time.Time
}

// ResigningManager implements a common interface for managing resigning keys
type ResigningManager interface {
	// AddPrivateKey adds a known private key to the manager, making it available
	// for resigning. The public key is implicitly added as a known key to the manager.
	AddPrivateKey(key nixtypes.NamedPrivateKey) error
	// AddPublicKey adds a known public key to the manager, making it available
	// as a matching key for a resigning operation
	AddPublicKey(key nixtypes.NamedPublicKey) error

	// DelPrivateKeyByName deletes a named private key from the manager. This will *not*
	// remove the public key, so a separate call to DelPublicKeyByName should also be made.
	DelPrivateKeyByName(keyName string) error
	// DelPublicKeyByName deletes a named public key from the manager. If a private key exists
	// matching the public key, an error will be returned.
	DelPublicKeyByName(keyName string) error

	// AddResigningRuleByName adds a mapping of a named public key to a named private key
	AddResigningRuleByName(srcKeyName string, destKeyName string, opts ...ResigningRuleOption) error
	// DelResigningRuleByName removes a resigning rule
	DelResigningRuleByName(srcKeyName string, destKeyName string, opts ...ResigningRuleOption) error

	// AddUnsignedRuleByName adds a key which unsigned packages should be signed with. Adding a rule implicitly
	// enables unsigned package resigning, which can be dangerous.
	AddUnsignedRuleByName(destKeyName string, opts ...ResigningRuleOption) error
	// DelUnsignedRuleByName removes a key which unsigned packages should be signed with.
	DelUnsignedRuleByName(destKeyName string, opts ...ResigningRuleOption) error

	// AddUnconditionalRuleByName adds a key which *all* packages should be signed with. Adding a rule implicitly
	// enabled unconfitional package resigning, which can be dangerous.
	AddUnconditionalRuleByName(destKeyName string, opts ...ResigningRuleOption) error
	// DelUnconditionalRuleByName
	DelUnconditionalRuleByName(destKeyName string, opts ...ResigningRuleOption) error
}

// sqliteResigningManager is a SQLite backed resigning manager. This is the default
// manager even when resigning rules are static.
type sqliteResigningManager struct {
}
