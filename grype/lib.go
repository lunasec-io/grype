package grype

import (
	"github.com/anchore/grype/grype/store"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

// TODO: store should be a minimal interface, not the full object
func FindVulnerabilities(store store.Store, userImageStr string, scopeOpt source.Scope, registryOptions *image.RegistryOptions) (match.Matches, pkg.Context, []pkg.Package, error) {
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

	return FindVulnerabilitiesForPackage(store, context.Distro, matchers, packages), context, packages, nil
}

// TODO: store should be a minimal interface, not the full object
func FindVulnerabilitiesForPackage(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) match.Matches {
	return matcher.FindMatches(store, d, matchers, packages)
}

func LoadVulnerabilityDB(cfg db.Config, update bool) (*store.Store, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, err
	}

	if update {
		log.Debug("looking for updates on vulnerability database")
		_, err := dbCurator.Update()
		if err != nil {
			return nil, err
		}
	}

	storeReader, err := dbCurator.GetStore()
	if err != nil {
		return nil, err
	}

	status := dbCurator.Status()

	p, err := db.NewVulnerabilityProvider(storeReader)
	if err != nil {
		return nil, err
	}
	
	s := &store.Store{
		Provider:          p,
		MetadataProvider:  db.NewVulnerabilityMetadataProvider(storeReader),
		ExclusionProvider: db.NewMatchExclusionProvider(storeReader),
		Status:            &status,
	}

	return s, status.Err
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
