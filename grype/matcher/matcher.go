package matcher

import (
	"github.com/lunasec-io/grype/grype/distro"
	"github.com/lunasec-io/grype/grype/match"
	"github.com/lunasec-io/grype/grype/pkg"
	"github.com/lunasec-io/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
	Match(vulnerability.Provider, *distro.Distro, pkg.Package) ([]match.Match, error)
}
