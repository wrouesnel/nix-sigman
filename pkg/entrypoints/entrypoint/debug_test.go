package entrypoint_test

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	. "gopkg.in/check.v1"
)

type DebugSuite struct{}

var _ = Suite(&DebugSuite{})

// writeTar writes a tarball of name/content pairs. Names ending in "/" are directories.
func writeTar(c *C, path string, files [][2]string) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	for _, file := range files {
		name, content := file[0], file[1]
		if strings.HasSuffix(name, "/") {
			c.Assert(tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Typeflag: tar.TypeDir}), IsNil)
			continue
		}
		c.Assert(tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}), IsNil)
		_, err := tw.Write([]byte(content))
		c.Assert(err, IsNil)
	}
	c.Assert(tw.Close(), IsNil)
	c.Assert(os.WriteFile(path, buf.Bytes(), os.FileMode(0644)), IsNil)
}

func (s *DebugSuite) TestExtractTarStaysInOutputDir(c *C) {
	baseDir := c.MkDir()
	outputDir := filepath.Join(baseDir, "out")
	tarFile := filepath.Join(baseDir, "input.tar")
	writeTar(c, tarFile, [][2]string{
		{"nar/", ""},
		{"nar/good.nar", "good"},
		{"../escaped.txt", "bad"},
		{"a/../../also.txt", "bad"},
	})

	entrypoint.Entrypoint([]string{"debug", "extract-tar", outputDir, tarFile},
		io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)

	content, err := os.ReadFile(filepath.Join(outputDir, "nar", "good.nar"))
	c.Assert(err, IsNil)
	c.Check(string(content), Equals, "good")

	for _, name := range []string{"escaped.txt", "also.txt"} {
		_, err := os.Stat(filepath.Join(baseDir, name))
		c.Check(os.IsNotExist(err), Equals, true, Commentf("%s was extracted outside the output dir", name))
	}
}
