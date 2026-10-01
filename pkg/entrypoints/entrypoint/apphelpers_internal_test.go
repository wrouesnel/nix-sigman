package entrypoint

import (
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
)

func TestBackNinfoUsesPathFilesystem(t *testing.T) {
	fs := afero.NewMemMapFs()
	path := pathlib.NewPath("/cache/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo", pathlib.PathWithAfero(fs))
	if err := path.Parent().MkdirAll(); err != nil {
		t.Fatal(err)
	}
	if err := path.WriteFile([]byte("original")); err != nil {
		t.Fatal(err)
	}

	if err := backNinfo(zap.NewNop(), path); err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	content, err := afero.ReadFile(fs, "/cache/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo.bak")
	if err != nil {
		t.Fatalf("backup not written to the path's filesystem: %v", err)
	}
	if string(content) != "original" {
		t.Errorf("unexpected backup content %q", content)
	}
}

func TestNarHashCheckMissingFile(t *testing.T) {
	path := pathlib.NewPath("/cache/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo", pathlib.PathWithAfero(afero.NewMemMapFs()))
	if _, _, err := narHashCheck(zap.NewNop(), path, nixtypes.NarInfo{URL: "nar/missing.nar"}); err == nil {
		t.Error("expected an error for a missing NAR file")
	}
}
