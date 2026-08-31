package resigning_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.yaml.in/yaml/v4"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type AstSuite struct {
}

var _ = Suite(&AstSuite{})

var sampleAst = `statements:
- if:
    and:
    - signed_by: loaded-key-1
    - signed_by: loaded-key-2
    - signed_by: loaded-key-3
    - not:
        signed_by: loaded-key-4
  then:
    sign_with: signing-key-1
`

func (a *AstSuite) TestAstParsing(c *C) {
	// Generate some fake keys
	m := map[string]nixtypes.NamedPrivateKey{}
	for _, name := range []string{"loaded-key-1", "loaded-key-2", "loaded-key-3", "loaded-key-4", "signing-key-1"} {
		key, _ := nixtypes.GeneratePrivateKey(name)
		m[name] = key
	}

	publicKeyAssigns := []string{}
	publicKeyUnmarshaler := func(out any, node *yaml.Node) error {
		value, found := m[node.Value]
		if !found {
			return fmt.Errorf("no public key is loaded named: %v", node.Value)
		}
		publicKeyAssigns = append(publicKeyAssigns, node.Value)
		*(out.(*nixtypes.NamedPublicKey)) = value.PublicKey()
		return nil
	}

	privateKeyAssigns := []string{}
	privateKeyUnmarshaler := func(out any, node *yaml.Node) error {
		value, found := m[node.Value]
		if !found {
			return fmt.Errorf("no private key is loaded named: %v", node.Value)
		}
		privateKeyAssigns = append(privateKeyAssigns, node.Value)
		*(out.(*nixtypes.NamedPrivateKey)) = value
		return nil
	}

	loader, err := yaml.NewLoader(bytes.NewBuffer([]byte(sampleAst)),
		yaml.Options(
			yaml.WithCustomTypeUnmarshaler(reflect.TypeFor[nixtypes.NamedPublicKey](), publicKeyUnmarshaler),
			yaml.WithCustomTypeUnmarshaler(reflect.TypeFor[nixtypes.NamedPrivateKey](), privateKeyUnmarshaler),
		))
	c.Assert(err, IsNil)

	root := new(resigning.ResigningNode)

	err = loader.Load(&root)
	c.Assert(err, IsNil)

	c.Assert(publicKeyAssigns, DeepEquals, []string{"loaded-key-1", "loaded-key-2", "loaded-key-3", "loaded-key-4"})
	c.Assert(privateKeyAssigns, DeepEquals, []string{"signing-key-1"})

	// The block above should validate
	c.Assert(root.Validate(), IsNil)

	// Check the AST is parsed successfully
	c.Assert(len(root.Statements), Equals, 1)
	stmt := root.Statements[0]
	c.Assert(stmt.If, Not(IsNil))
	c.Assert(stmt.If, Not(IsNil))
	c.Assert(stmt.If.And, Not(IsNil))
	c.Assert(len(stmt.If.And), Equals, 4)
	c.Assert(stmt.If.And[0].SignedBy, Not(IsNil))
	c.Assert(stmt.If.And[1].SignedBy, Not(IsNil))
	c.Assert(stmt.If.And[2].SignedBy, Not(IsNil))
	c.Assert(stmt.If.And[3].Not, Not(IsNil))
	c.Assert(stmt.If.And[3].Not.SignedBy, Not(IsNil))
	c.Assert(stmt.Then.SignWith, Not(IsNil))
}
