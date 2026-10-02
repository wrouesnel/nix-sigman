package httpauth_test

import (
	"context"
	"encoding/base64"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	. "gopkg.in/check.v1"
)

type Argon2Suite struct{}

var _ = Suite(&Argon2Suite{})

// fastHash builds a hash with cheap parameters so tests stay quick.
func fastHash(variant, password string) string {
	h := &httpauth.Argon2Hash{Variant: variant, Memory: 64, Time: 1, Threads: 1, Salt: []byte("0123456789abcdef")}
	if variant == "argon2i" {
		h.Key = argon2.Key([]byte(password), h.Salt, h.Time, h.Memory, h.Threads, 32)
	} else {
		h.Key = argon2.IDKey([]byte(password), h.Salt, h.Time, h.Memory, h.Threads, 32)
	}
	return h.String()
}

func (s *Argon2Suite) TestHashPasswordRoundTrip(c *C) {
	encoded, err := httpauth.HashPassword("hunter2")
	c.Assert(err, IsNil)
	c.Check(strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=4$"), Equals, true, Commentf(encoded))

	h, err := httpauth.ParseArgon2Hash(encoded)
	c.Assert(err, IsNil)
	c.Check(h.Variant, Equals, "argon2id")
	c.Check(h.Memory, Equals, uint32(httpauth.DefaultArgon2Memory))
	c.Check(h.Time, Equals, uint32(httpauth.DefaultArgon2Time))
	c.Check(h.Threads, Equals, uint8(httpauth.DefaultArgon2Threads))
	c.Check(h.Salt, HasLen, httpauth.Argon2SaltLen)
	c.Check(h.Key, HasLen, httpauth.Argon2KeyLen)
	c.Check(h.Verify("hunter2"), Equals, true)
	c.Check(h.Verify("hunter3"), Equals, false)
	c.Check(h.String(), Equals, encoded)
}

func (s *Argon2Suite) TestHashPasswordUsesRandomSalt(c *C) {
	a, err := httpauth.HashPassword("x")
	c.Assert(err, IsNil)
	b, err := httpauth.HashPassword("x")
	c.Assert(err, IsNil)
	c.Check(a, Not(Equals), b)
}

func (s *Argon2Suite) TestStringRoundTrip(c *C) {
	encoded := fastHash("argon2id", "pw")
	h, err := httpauth.ParseArgon2Hash(encoded)
	c.Assert(err, IsNil)
	c.Check(h.String(), Equals, encoded)
	c.Check(h.Memory, Equals, uint32(64))
	c.Check(h.Time, Equals, uint32(1))
	c.Check(h.Threads, Equals, uint8(1))
	c.Check(string(h.Salt), Equals, "0123456789abcdef")
}

func (s *Argon2Suite) TestArgon2iVariant(c *C) {
	encoded := fastHash("argon2i", "pw")
	c.Check(strings.HasPrefix(encoded, "$argon2i$"), Equals, true)
	h, err := httpauth.ParseArgon2Hash(encoded)
	c.Assert(err, IsNil)
	c.Check(h.Variant, Equals, "argon2i")
	c.Check(h.Verify("pw"), Equals, true)
	c.Check(h.Verify("PW"), Equals, false)

	// The variant must actually select the algorithm: an argon2i key relabelled as
	// argon2id must not verify.
	relabelled := "$argon2id" + strings.TrimPrefix(encoded, "$argon2i")
	h2, err := httpauth.ParseArgon2Hash(relabelled)
	c.Assert(err, IsNil)
	c.Check(h2.Verify("pw"), Equals, false)
}

func (s *Argon2Suite) TestParseRejectsMalformed(c *C) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	valid := "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key
	_, err := httpauth.ParseArgon2Hash(valid)
	c.Assert(err, IsNil)

	cases := map[string]string{
		"argon2d variant":   "$argon2d$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"version junk":      "$argon2id$v=19x$m=64,t=1,p=1$" + salt + "$" + key,
		"param junk":        "$argon2id$v=19$m=64,t=1,p=1,x=5$" + salt + "$" + key,
		"huge memory":       "$argon2id$v=19$m=4294967295,t=1,p=1$" + salt + "$" + key,
		"huge time":         "$argon2id$v=19$m=64,t=1000,p=1$" + salt + "$" + key,
		"bcrypt":            "$2y$10$abcdefghijklmnopqrstuuWzM7aFZr0b5Fh4b5KX7v6Yx1Ty5k8g2",
		"empty":             "",
		"no leading dollar": "argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "$",
		"too few fields":    "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"too many fields":   valid + "$extra",
		"old version":       "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"bad version":       "$argon2id$version=19$m=64,t=1,p=1$" + salt + "$" + key,
		"bad params":        "$argon2id$v=19$m=x,t=1,p=1$" + salt + "$" + key,
		"missing params":    "$argon2id$v=19$m=64$" + salt + "$" + key,
		"t=0":               "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"p=0":               "$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"p overflow":        "$argon2id$v=19$m=64,t=1,p=256$" + salt + "$" + key,
		"negative memory":   "$argon2id$v=19$m=-1,t=1,p=1$" + salt + "$" + key,
		"bad salt base64":   "$argon2id$v=19$m=64,t=1,p=1$!!!$" + key,
		"bad hash base64":   "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!!",
		"padded base64":     "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + base64.StdEncoding.EncodeToString([]byte("k")),
		"empty hash":        "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$",
	}
	for name, encoded := range cases {
		h, err := httpauth.ParseArgon2Hash(encoded)
		c.Check(err, NotNil, Commentf("%s: %q", name, encoded))
		c.Check(h, IsNil, Commentf(name))
	}
}

func writeFile(c *C, dir, name, content string) string {
	p := filepath.Join(dir, name)
	c.Assert(os.WriteFile(p, []byte(content), 0o600), IsNil)
	return p
}

func (s *Argon2Suite) TestLoadPasswordFiles(c *C) {
	dir := c.MkDir()
	first := writeFile(c, dir, "first", strings.Join([]string{
		"# a comment",
		"",
		"   ",
		"alice:" + fastHash("argon2id", "alice-old"),
		"  # indented comment",
		"bob:" + fastHash("argon2i", "bob-pw"),
	}, "\n")+"\n")
	second := writeFile(c, dir, "second", "  alice:"+fastHash("argon2id", "alice-new")+"  \n")

	a, err := httpauth.LoadPasswordFiles(first, second)
	c.Assert(err, IsNil)
	c.Check(a.Users(), Equals, 2)
	c.Check(a.Name(), Equals, "password-file")

	ctx := context.Background()
	check := func(user, pw string, expected httpauth.Result) {
		result, err := a.Authenticate(ctx, user, pw)
		c.Check(err, IsNil)
		c.Check(result, Equals, expected, Commentf("%s/%s", user, pw))
	}
	check("alice", "alice-new", httpauth.Allowed)
	check("alice", "alice-old", httpauth.Denied) // overridden by the later file
	check("bob", "bob-pw", httpauth.Allowed)
	check("bob", "wrong", httpauth.Denied)
	check("bob", "", httpauth.Denied)
	check("mallory", "bob-pw", httpauth.Denied)
	check("", "", httpauth.Denied)
}

func (s *Argon2Suite) TestLoadPasswordFilesNoFiles(c *C) {
	a, err := httpauth.LoadPasswordFiles()
	c.Assert(err, IsNil)
	c.Check(a.Users(), Equals, 0)
	result, err := a.Authenticate(context.Background(), "anyone", "")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *Argon2Suite) TestLoadPasswordFilesMalformedLine(c *C) {
	dir := c.MkDir()
	good := "alice:" + fastHash("argon2id", "pw") + "\n"

	noColon := writeFile(c, dir, "nocolon", "# comment\n"+good+"justausername\n")
	_, err := httpauth.LoadPasswordFiles(noColon)
	c.Assert(err, NotNil)
	c.Check(err.Error(), Equals, noColon+":3: expected username:hash")

	noUser := writeFile(c, dir, "nouser", ":"+fastHash("argon2id", "pw")+"\n")
	_, err = httpauth.LoadPasswordFiles(noUser)
	c.Assert(err, NotNil)
	c.Check(err.Error(), Equals, noUser+":1: expected username:hash")

	badHash := writeFile(c, dir, "badhash", good+"\nbob:$argon2d$v=19$m=64,t=1,p=1$c2FsdA$a2V5\n")
	_, err = httpauth.LoadPasswordFiles(badHash)
	c.Assert(err, NotNil)
	c.Check(err.Error(), Equals, badHash+`:3: unsupported argon2 variant "argon2d"`)

	// An error in a later file is still reported.
	goodFile := writeFile(c, dir, "good", good)
	_, err = httpauth.LoadPasswordFiles(goodFile, badHash)
	c.Check(err, ErrorMatches, ".*badhash:3:.*")
}

func (s *Argon2Suite) TestLoadPasswordFilesMissingFile(c *C) {
	missing := filepath.Join(c.MkDir(), "missing")
	_, err := httpauth.LoadPasswordFiles(missing)
	c.Assert(err, NotNil)
	c.Check(os.IsNotExist(err), Equals, true, Commentf("%v", err))
}
