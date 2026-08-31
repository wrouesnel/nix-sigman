package resigning

import (
	"errors"
	"reflect"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
)

// ResigningNode is the common interface to allow scripting the resigning operations
// daemon.
type ResigningNode struct {
	Statements []*ResigningNode `yaml:"statements,omitempty"`
	// If/then in a usefully sized block
	If   *ResigningNode `yaml:"if,omitempty"`
	Then *ResigningNode `yaml:"then,omitempty"`

	And    []*ResigningNode `yaml:"and,omitempty"`
	Or     []*ResigningNode `yaml:"or,omitempty"`
	Not    *ResigningNode   `yaml:"not,omitempty"`
	Signed *struct {
	} `yaml:"signed,omitempty"`
	SignedBy *nixtypes.NamedPublicKey  `yaml:"signed_by,omitempty"`
	SignWith *nixtypes.NamedPrivateKey `yaml:"sign_with,omitempty"`
}

func (r *ResigningNode) Validate() error {
	val := reflect.ValueOf(r).Elem()
	numFields := val.NumField()
	numNil := 0
	for _, value := range val.Fields() {
		if value.IsNil() {
			numNil += 1
		}
	}
	if numNonNil := numFields - numNil; numNonNil > 1 {
		// Special case if/then blocks
		if !(r.If != nil && r.Then != nil) {
			return errors.New("got multiple operands for a resigning node")
		}
	} else if numNonNil == 0 {
		return errors.New("got no operands for a resigning node")
	}

	switch {
	case r.Statements != nil:
		for _, node := range r.Statements {
			if err := node.Validate(); err != nil {
				return err
			}
		}
	case r.If != nil:
		if err := r.If.Validate(); err != nil {
			return err
		}
		if r.Then == nil {
			return errors.New("if without then in block")
		}
		if err := r.Then.Validate(); err != nil {
			return err
		}
	case r.Then != nil:
		// If/Then is fully validated by If
		if r.If == nil {
			return errors.New("then without if in block")
		}
	case r.And != nil:
		for _, node := range r.And {
			if err := node.Validate(); err != nil {
				return err
			}
		}
	case r.Or != nil:
		for _, node := range r.Or {
			if err := node.Validate(); err != nil {
				return err
			}
		}
	case r.Not != nil:
		return r.Not.Validate()
	}
	return nil
}

func (r *ResigningNode) Execute(ninfo *nixtypes.NarInfo) bool {
	switch {
	case r.Statements != nil:
		for _, statement := range r.Statements {
			statement.Execute(ninfo)
		}
		return true
	case r.If != nil:
		if r.If.Execute(ninfo) {
			return r.Then.Execute(ninfo)
		}
		return false
	case r.And != nil:
		return lo.Reduce(r.And, func(agg bool, item *ResigningNode, index int) bool {
			if !agg {
				return agg
			}
			return item.Execute(ninfo)
		}, true)
	case r.Or != nil:
		return lo.Reduce(r.Or, func(agg bool, item *ResigningNode, index int) bool {
			if agg {
				return agg
			}
			return item.Execute(ninfo)
		}, false)
	case r.Not != nil:
		return !r.Not.Execute(ninfo)
	case r.Signed != nil:
		// Check if the narinfo has _any_ signatures
		return len(lo.CoalesceSliceOrEmpty(ninfo.Sig)) > 0
	case r.SignedBy != nil:
		validSignature, _ := ninfo.Verify(*r.SignedBy)
		return validSignature
	case r.SignWith != nil:
		_, _, err := ninfo.Sign(*r.SignWith)
		if err != nil {
			return false
		}
		return true
	}
	return false
}
