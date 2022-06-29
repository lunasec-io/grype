package grype

import (
	"github.com/wagoodman/go-partybus"

	"github.com/lunasec-io/grype/grype/db"
	"github.com/lunasec-io/grype/grype/logger"
	"github.com/lunasec-io/grype/grype/match"
	"github.com/lunasec-io/grype/grype/matcher"
	"github.com/lunasec-io/grype/grype/pkg"
	"github.com/lunasec-io/grype/grype/vulnerability"
	"github.com/lunasec-io/grype/internal/bus"
	"github.com/lunasec-io/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

func FindVulnerabilities(provider vulnerability.Provider, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
	providerConfig := pkg.ProviderConfig{
		RegistryOptions:   registryOptions,
		CatalogingOptions: cataloger.DefaultConfig(),
	}
	providerConfig.CatalogingOptions.Search.Scope = scopeOpt

	packages, context, err := pkg.Provide(userImageStr, providerConfig)
	if err != nil {
		return match.Matches{}, pkg.Context{}, nil, err
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	return FindVulnerabilitiesForPackage(provider, context.Distro, matchers, packages), context, packages, nil
}

func FindVulnerabilitiesForPackage(provider vulnerability.Provider, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) match.Matches {
	return matcher.FindMatches(provider, d, matchers, packages)
}

func LoadVulnerabilityDB(cfg db.Config, update bool) (vulnerability.Provider, vulnerability.MetadataProvider, *db.Status, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	if update {
		log.Debug("looking for updates on vulnerability database")
		_, err := dbCurator.Update()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	store, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, nil, err
	}

	status := dbCurator.Status()

	return db.NewVulnerabilityProvider(store), db.NewVulnerabilityMetadataProvider(store), &status, status.Err
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
