package certpg

type Ident struct {
	Id           int
	Organization string
	Province     string
	Country      string
}

func ScanIdent(row Scanner, ident *Ident) error {
	return row.Scan(
		&ident.Id,
		&ident.Organization,
		&ident.Province,
		&ident.Country,
	)
}
