package javascript

import (
	"github.com/lunasec-io/grype/grype/distro"
	"github.com/lunasec-io/grype/grype/match"
	"github.com/lunasec-io/grype/grype/pkg"
	"github.com/lunasec-io/grype/grype/search"
	"github.com/lunasec-io/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.NpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JavascriptMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	return search.ByCriteria(store, d, p, m.Type(), search.CommonCriteria...)
}
