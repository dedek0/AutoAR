package db

// Package-level wrappers for the bug-bounty program catalog.

func UpsertCatalogProgram(c CatalogProgram) (int64, error) {
	database, err := getInitializedDB()
	if err != nil {
		return 0, err
	}
	return database.UpsertCatalogProgram(c)
}

func ReplaceCatalogDomains(programID int64, domains []CatalogDomain) error {
	database, err := getInitializedDB()
	if err != nil {
		return err
	}
	return database.ReplaceCatalogDomains(programID, domains)
}

func ClearCatalogSource(source string) error {
	database, err := getInitializedDB()
	if err != nil {
		return err
	}
	return database.ClearCatalogSource(source)
}

func SearchCatalogByKeyword(q string, limit int) ([]CatalogProgram, error) {
	database, err := getInitializedDB()
	if err != nil {
		return nil, err
	}
	return database.SearchCatalogByKeyword(q, limit)
}

func SearchCatalogByDomain(q string, limit int) ([]CatalogDomainMatch, error) {
	database, err := getInitializedDB()
	if err != nil {
		return nil, err
	}
	return database.SearchCatalogByDomain(q, limit)
}

func CatalogCounts() (int, int, error) {
	database, err := getInitializedDB()
	if err != nil {
		return 0, 0, err
	}
	return database.CatalogCounts()
}
