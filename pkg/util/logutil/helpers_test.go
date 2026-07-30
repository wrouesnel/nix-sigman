package logutil

import (
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&UnitTestSuite{})

type UnitTestSuite struct{}

func (u *UnitTestSuite) TestLogWriter(c *C) {
	lines := []string{}
	fn := func(line string) {
		lines = append(lines, line)
	}

	wr := NewLogWriter(fn)

	testStrings := []string{"hello", "goodbye", "yesterday", "tomorrow", "daffodil"}

	for _, line := range testStrings {
		_, err := wr.Write(append([]byte(line), '\n'))
		c.Assert(err, IsNil)
	}

	for idx, line := range testStrings {
		c.Assert(lines[idx], Equals, line)
	}

	for _, line := range testStrings {
		_, err := wr.Write([]byte(line))
		c.Assert(err, IsNil)
	}

	wr.Write([]byte("\n"))
	c.Assert(lines[len(lines)-1], Equals, strings.Join(testStrings, ""))
}
