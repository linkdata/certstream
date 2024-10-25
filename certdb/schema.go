package certdb

var TablePrefix = "certdb_"

var TableOperator = &TableInfo{
	Name:      "operator",
	Columns:   []string{"name", "email"},
	Conflicts: []string{"name", "email"},
	HasId:     true,
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
name VARCHAR(128) NOT NULL,
email VARCHAR(256) NOT NULL
);
{ConflictIndex}
`,
}

var TableStream = &TableInfo{
	Name:      "stream",
	Columns:   []string{"url", "operator", "lastindex", "json"},
	Conflicts: []string{"url", "operator"},
	HasId:     true,
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
url VARCHAR(128) NOT NULL, -- CT log stream URL
operator BIGINT NOT NULL, -- operator.id
lastindex BIGINT NOT NULL, -- last CT log entry index written
json TEXT NOT NULL
);
{ConflictIndex}
`,
}

var TableCert = &TableInfo{
	Name:      "cert",
	Columns:   []string{"sig", "notbefore", "notafter", "organization", "province", "country"},
	Conflicts: []string{"sig"},
	HasId:     true,
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
sig VARCHAR(64) NOT NULL,
notbefore TIMESTAMP NOT NULL,
notafter TIMESTAMP NOT NULL,
organization TEXT,
province TEXT,
country TEXT
);
{ConflictIndex}
CREATE INDEX IF NOT EXISTS {TableName}_notbefore_idx ON {TableName} (notbefore);
CREATE INDEX IF NOT EXISTS {TableName}_notafter_idx ON {TableName} (notafter);
`,
}

var TableEntry = &TableInfo{
	Name:       "entry",
	ForeignKey: "stream",
	Columns:    []string{"stream", "index", "cert"},
	Conflicts:  []string{"stream", "index"},
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
stream BIGINT NOT NULL, -- stream.id
index BIGINT NOT NULL, -- CT log entry index
cert BIGINT NOT NULL, -- cert.id
PRIMARY KEY (stream, index)
);
{AlterTableForeignKey}
`,
}

var TableDNSName = &TableInfo{
	Name:       "dnsname",
	ForeignKey: "cert",
	Columns:    []string{"cert", "name", "rname"},
	Conflicts:  []string{"cert", "name"},
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
name VARCHAR(256) NOT NULL, -- e.g. 'foo.example.com'
rname VARCHAR(256) NOT NULL, -- e.g. 'com.example.foo'
PRIMARY KEY (cert, name)
);
CREATE INDEX IF NOT EXISTS {TableName}_name_idx ON {TableName} (name);
CREATE INDEX IF NOT EXISTS {TableName}_rname_idx ON {TableName} (rname);
{AlterTableForeignKey}
`,
}

var TableIPAddress = &TableInfo{
	Name:       "ipaddress",
	ForeignKey: "cert",
	Columns:    []string{"cert", "addr"},
	Conflicts:  []string{"cert", "addr"},
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
addr VARCHAR(45) NOT NULL, -- e.g. '192.168.1.1'
PRIMARY KEY (cert, addr)
);
CREATE INDEX IF NOT EXISTS {TableName}_addr_idx ON {TableName} (addr);
{AlterTableForeignKey}
`,
}

var TableEmail = &TableInfo{
	Name:       "email",
	ForeignKey: "cert",
	Columns:    []string{"cert", "email"},
	Conflicts:  []string{"cert", "email"},
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
email VARCHAR(128) NOT NULL, -- e.g. 'user@example.com'
PRIMARY KEY (cert, email)
);
CREATE INDEX IF NOT EXISTS {TableName}_email_idx ON {TableName} (email);
{AlterTableForeignKey}
`,
}

var TableURI = &TableInfo{
	Name:       "uri",
	ForeignKey: "cert",
	Columns:    []string{"cert", "uri"},
	Conflicts:  []string{"cert", "uri"},
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
uri VARCHAR(1024) NOT NULL, -- e.g. 'https://www.example.com/path'
PRIMARY KEY (cert, uri)
);
CREATE INDEX IF NOT EXISTS {TableName}_uri_idx ON {TableName} (uri);
{AlterTableForeignKey}
`,
}
