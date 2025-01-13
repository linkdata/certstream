package certstream

type PgIdent struct {
	Id           int
	Organization string
	Province     string
	Country      string
}

func ScanIdent(row Scanner, ident *PgIdent) error {
	return row.Scan(
		&ident.Id,
		&ident.Organization,
		&ident.Province,
		&ident.Country,
	)
}
