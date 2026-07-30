package serve

import (
	"context"
	"time"

	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"github.com/wrouesnel/nix-sigman/pkg/util/logutil"
)

// Serve implements a Nix HTTP cache server by reading an extant `/nix` directory
// in flatfile format. It is possible, though not advised, to share this with a system
// nix-daemon.
type ServeCLI struct {
	resigning.ResigningConfig `embed:""`
	Listen                    []string      `         help:"Listen addresses"                                                                             default:"tcp://127.0.0.1:8081"`
	Root                      string        `         help:"Root to search for a nix store"                                                               default:"/"`
	NixDB                     *string       `         help:"Override the database location"`
	StoreRoot                 *string       `         help:"Override the store root (but not the store path)"`
	StorePath                 string        `         help:"Nix store path to advertise (usually should not be changed)"                                  default:"/nix/store"`
	Priority                  int           `         help:"Nix store priority - lower means greater"                                                     default:"40"`
	WantMassQuery             bool          `         help:"Set the WantMassQuery flag"                                                                   default:"true"`
	RequiredSignatures        []string      `         help:"Return 404 for narinfo if named signatures are not valid on the NARinfo file after resigning"`
	NarInfoFreshDuration      time.Duration `         help:"Default cache-control to put on NARinfo file responses"                                       default:"0s"`
}

func (d *ServeCLI) Run(ctx context.Context) (err error) {
	l := logutil.FromCtx(ctx)
}
