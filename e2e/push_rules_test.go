package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

// PushRulesSuite runs a push-enabled server and drives it with the nix client: a user
// adds a resigning rule over HTTP, pushes paths with nix copy, and deletes the rule.
type PushRulesSuite struct {
	binary string

	dir      string
	src      string
	dst      string
	baseURL  string
	server   *exec.Cmd
	logFile  *os.File
	nixEnv   []string
	paths    map[string]string
	pubKeys  map[string]string
	keyFiles []string
}

var _ = Suite(&PushRulesSuite{})

func (s *PushRulesSuite) SetUpSuite(c *C) {
	if _, err := exec.LookPath("nix"); err != nil {
		c.Skip("nix command not available")
	}
	if runtime.GOOS == "windows" {
		c.Skip("push is not supported on windows")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	s.binary = filepath.Join(c.MkDir(), "nix-sigman")
	build := exec.Command("go", "build", "-o", s.binary, "./cmd/nix-sigman")
	build.Dir = filepath.Join(filepath.Dir(thisFile), "..")
	out, err := build.CombinedOutput()
	c.Assert(err, IsNil, Commentf("building nix-sigman: %s", out))
}

// run runs a command, failing the test on error, and returns its stdout.
func (s *PushRulesSuite) run(c *C, stdin string, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = s.dir
	cmd.Env = s.nixEnv
	cmd.Stdin = strings.NewReader(stdin)
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	out, err := cmd.Output()
	c.Assert(err, IsNil, Commentf("%s %v: %s", name, args, stderr))
	return string(out)
}

func (s *PushRulesSuite) writeFile(c *C, name, content string) string {
	p := filepath.Join(s.dir, name)
	c.Assert(os.WriteFile(p, []byte(content), 0o600), IsNil)
	return p
}

func freePort(c *C) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, IsNil)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (s *PushRulesSuite) SetUpTest(c *C) {
	s.dir = c.MkDir()
	s.src = "local?root=" + filepath.Join(s.dir, "src")
	s.dst = "local?root=" + filepath.Join(s.dir, "dst")
	port := freePort(c)
	s.baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	// Keep the client's narinfo cache and config out of the user's home.
	netrc := s.writeFile(c, "netrc", "machine 127.0.0.1 login ci password ci-pw\n")
	s.nixEnv = append(os.Environ(),
		"HOME="+s.dir,
		"XDG_CACHE_HOME="+filepath.Join(s.dir, "cache"),
		"XDG_CONFIG_HOME="+filepath.Join(s.dir, "config"),
		"NIX_CONFIG=experimental-features = nix-command\nnetrc-file = "+netrc,
	)

	s.pubKeys = map[string]string{}
	s.keyFiles = nil
	for _, name := range []string{"release-1", "other-1"} {
		secret := s.run(c, "", "nix", "key", "generate-secret", "--key-name", name)
		s.keyFiles = append(s.keyFiles, s.writeFile(c, name+".sec", secret))
		s.pubKeys[name] = strings.TrimSpace(s.run(c, secret, "nix", "key", "convert-secret-to-public"))
	}

	// Create the destination store's database, and some paths to push.
	s.run(c, "", "nix", "store", "info", "--store", s.dst)
	s.paths = map[string]string{}
	for _, name := range []string{"app-a", "app-b", "app-c"} {
		file := s.writeFile(c, name, "content of "+name+"\n")
		s.paths[name] = strings.TrimSpace(s.run(c, "", "nix", "store", "add-file", "--store", s.src, file))
	}

	passwords := ""
	for _, user := range []string{"ci", "admin", "nobody"} {
		passwords += s.run(c, user+"-pw\n", s.binary, "debug", "hash-password", "--username", user)
	}
	passwordFile := s.writeFile(c, "passwd", passwords)
	aclFile := s.writeFile(c, "acl.yml", `admins:
  users: [admin]
grants:
  - users: [ci]
    keys: [release-1]
`)

	args := []string{}
	for _, keyFile := range s.keyFiles {
		args = append(args, "--private-key-files", keyFile)
	}
	args = append(args, "serve",
		"--root", filepath.Join(s.dir, "dst"),
		"--listen", "tcp://127.0.0.1:"+fmt.Sprint(port),
		"--push-enabled",
		"--push-password-file", passwordFile,
		"--push-rules-acl-file", aclFile,
		"--push-staging-dir", c.MkDir(),
	)
	var err error
	s.logFile, err = os.Create(filepath.Join(s.dir, "server.log"))
	c.Assert(err, IsNil)
	s.server = exec.Command(s.binary, args...)
	s.server.Stdout = s.logFile
	s.server.Stderr = s.logFile
	c.Assert(s.server.Start(), IsNil)

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(s.baseURL + "/nix-cache-info")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			c.Fatalf("server did not start: %s", s.serverLog())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *PushRulesSuite) serverLog() string {
	content, _ := os.ReadFile(filepath.Join(s.dir, "server.log"))
	return string(content)
}

func (s *PushRulesSuite) TearDownTest(c *C) {
	if s.server != nil && s.server.Process != nil {
		_ = s.server.Process.Kill()
		_ = s.server.Wait()
	}
	if s.logFile != nil {
		s.logFile.Close()
	}
	if c.Failed() {
		c.Log(s.serverLog())
	}
	// Store paths are read-only, which stops the test directories being removed.
	_ = filepath.WalkDir(s.dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}

// api makes a rules API request, decoding a JSON response into out if non-nil.
func (s *PushRulesSuite) api(c *C, user, method, path string, body any, out any) int {
	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		c.Assert(err, IsNil)
		reqBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, s.baseURL+path, reqBody)
	c.Assert(err, IsNil)
	if user != "" {
		req.SetBasicAuth(user, user+"-pw")
	}
	resp, err := http.DefaultClient.Do(req)
	c.Assert(err, IsNil)
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	if out != nil && resp.StatusCode < 300 {
		c.Assert(json.Unmarshal(content, out), IsNil, Commentf("%s", content))
	}
	return resp.StatusCode
}

type rule struct {
	ID       string     `json:"id"`
	Owner    string     `json:"owner"`
	SignWith []string   `json:"sign_with"`
	Expires  *time.Time `json:"expires"`
}

type ruleList struct {
	Rules []rule `json:"rules"`
}

type deleted struct {
	Deleted int `json:"deleted"`
}

func (s *PushRulesSuite) push(c *C, names ...string) {
	args := []string{"copy", "--from", s.src, "--to", s.baseURL}
	for _, name := range names {
		args = append(args, s.paths[name])
	}
	s.run(c, "", "nix", args...)
}

type pathInfo struct {
	Signatures []string `json:"signatures"`
}

// signatures returns the signatures the destination store's database has for a path.
func (s *PushRulesSuite) signatures(c *C, name string) []string {
	out := s.run(c, "", "nix", "path-info", "--store", s.dst, "--json", "--json-format", "1", s.paths[name])
	infos := map[string]pathInfo{}
	c.Assert(json.Unmarshal([]byte(out), &infos), IsNil, Commentf("%s", out))
	info, found := infos[s.paths[name]]
	c.Assert(found, Equals, true, Commentf("%s", out))
	return info.Signatures
}

// verify checks a path in the destination store has a valid signature from key.
func (s *PushRulesSuite) verify(c *C, name, key string) bool {
	cmd := exec.Command("nix", "store", "verify", "--store", s.dst, "--sigs-needed", "1",
		"--trusted-public-keys", s.pubKeys[key], s.paths[name])
	cmd.Env = s.nixEnv
	return cmd.Run() == nil
}

func (s *PushRulesSuite) TestAddPushAndDeleteRule(c *C) {
	// Rules need credentials, and a grant for every key they sign with.
	c.Check(s.api(c, "", http.MethodGet, "/_sigman/rules", nil, nil), Equals, http.StatusUnauthorized)
	c.Check(s.api(c, "nobody", http.MethodGet, "/_sigman/rules", nil, nil), Equals, http.StatusForbidden)
	c.Check(s.api(c, "ci", http.MethodPost, "/_sigman/rules",
		map[string]any{"sign_with": []string{"other-1"}}, nil), Equals, http.StatusForbidden)

	var created rule
	c.Assert(s.api(c, "ci", http.MethodPost, "/_sigman/rules", map[string]any{
		"description": "release builds",
		"condition":   map[string]any{"or": []any{map[string]any{"name": "app-a"}, map[string]any{"name": "app-b"}}},
		"sign_with":   []string{"release-1"},
		"expires_in":  "1h",
	}, &created), Equals, http.StatusCreated)
	c.Check(created.Owner, Equals, "ci")
	c.Check(created.Expires, NotNil)

	var listed ruleList
	c.Assert(s.api(c, "ci", http.MethodGet, "/_sigman/rules", nil, &listed), Equals, http.StatusOK)
	c.Assert(listed.Rules, HasLen, 1)
	c.Check(listed.Rules[0].ID, Equals, created.ID)
	// Rules belong to their owner.
	c.Check(s.api(c, "nobody", http.MethodDelete, "/_sigman/rules/"+created.ID, nil, nil), Equals, http.StatusForbidden)

	// Paths the rule matches are signed as they're pushed, and the signature is stored.
	s.push(c, "app-a", "app-c")
	c.Check(s.verify(c, "app-a", "release-1"), Equals, true)
	c.Check(s.signatures(c, "app-c"), HasLen, 0)

	// The served narinfo carries the stored signature.
	resp, err := http.Get(s.baseURL + "/" + strings.SplitN(filepath.Base(s.paths["app-a"]), "-", 2)[0] + ".narinfo")
	c.Assert(err, IsNil)
	narinfo, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	c.Check(strings.Contains(string(narinfo), "Sig: release-1:"), Equals, true, Commentf("%s", narinfo))

	var gone deleted
	c.Assert(s.api(c, "ci", http.MethodDelete, "/_sigman/rules/"+created.ID, nil, &gone), Equals, http.StatusOK)
	c.Check(gone.Deleted, Equals, 1)
	c.Assert(s.api(c, "ci", http.MethodGet, "/_sigman/rules", nil, &listed), Equals, http.StatusOK)
	c.Check(listed.Rules, HasLen, 0)
	c.Check(s.api(c, "ci", http.MethodGet, "/_sigman/rules/"+created.ID, nil, nil), Equals, http.StatusNotFound)

	// Once deleted, the rule no longer signs pushes, but what it signed stays signed.
	s.push(c, "app-b")
	c.Check(s.signatures(c, "app-b"), HasLen, 0)
	c.Check(s.verify(c, "app-a", "release-1"), Equals, true)
}

func (s *PushRulesSuite) TestBulkDeleteByKey(c *C) {
	for range 3 {
		c.Assert(s.api(c, "ci", http.MethodPost, "/_sigman/rules",
			map[string]any{"sign_with": []string{"release-1"}}, nil), Equals, http.StatusCreated)
	}
	// Admins must say what to delete.
	c.Check(s.api(c, "admin", http.MethodDelete, "/_sigman/rules", nil, nil), Equals, http.StatusBadRequest)

	var listed ruleList
	c.Assert(s.api(c, "admin", http.MethodGet, "/_sigman/rules", nil, &listed), Equals, http.StatusOK)
	c.Check(listed.Rules, HasLen, 3)

	var gone deleted
	c.Assert(s.api(c, "admin", http.MethodDelete, "/_sigman/rules?sign_with=release-1", nil, &gone), Equals, http.StatusOK)
	c.Check(gone.Deleted, Equals, 3)

	s.push(c, "app-a")
	c.Check(s.signatures(c, "app-a"), HasLen, 0)
}

func (s *PushRulesSuite) TestExpiredRuleStopsSigning(c *C) {
	c.Assert(s.api(c, "ci", http.MethodPost, "/_sigman/rules",
		map[string]any{"sign_with": []string{"release-1"}, "expires_in": "1s"}, nil), Equals, http.StatusCreated)
	time.Sleep(1500 * time.Millisecond)

	var listed ruleList
	c.Assert(s.api(c, "ci", http.MethodGet, "/_sigman/rules", nil, &listed), Equals, http.StatusOK)
	c.Check(listed.Rules, HasLen, 0)
	s.push(c, "app-a")
	c.Check(s.signatures(c, "app-a"), HasLen, 0)
}
