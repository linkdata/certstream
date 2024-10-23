package certdb

var TablePrefix = "certdb_"

var TableOperator = &TableInfo{
	Name: "operator",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
domain VARCHAR(128) NOT NULL,
name VARCHAR(128) NOT NULL,
email VARCHAR(128) NOT NULL
);
`,
	Upsert: ``,
}

var TableStream = &TableInfo{
	Name:       "stream",
	ForeignKey: "operator",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
operator BIGINT NOT NULL, -- operator.id
url VARCHAR(256) NOT NULL, -- CT log stream URL
lastindex BIGINT NOT NULL, -- last CT log entry index written
json TEXT NOT NULL
);
{AlterTableForeignKey}
`,
	Upsert: ``,
}

var TableCert = &TableInfo{
	Name:       "cert",
	ForeignKey: "stream",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
id BIGINT {IdColumnConstraint},
stream BIGINT NOT NULL, -- stream.id
index BIGINT NOT NULL, -- CT log entry index
seen TIMESTAMP NOT NULL,
notbefore TIMESTAMP NOT NULL,
notafter TIMESTAMP NOT NULL,
json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS {TableName}_notbefore_idx ON {TableName} (notbefore);
CREATE INDEX IF NOT EXISTS {TableName}_notafter_idx ON {TableName} (notafter);
{AlterTableForeignKey}
`,
	Upsert: ``,
}

var TableDNSName = &TableInfo{
	Name:       "dnsname",
	ForeignKey: "cert",
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
	Upsert: ``,
}

var TableIPAddress = &TableInfo{
	Name:       "ipaddress",
	ForeignKey: "cert",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
addr VARCHAR(45) NOT NULL, -- e.g. '192.168.1.1'
PRIMARY KEY (cert, addr)
);
CREATE INDEX IF NOT EXISTS {TableName}_addr_idx ON {TableName} (addr);
{AlterTableForeignKey}
`,
	Upsert: ``,
}

var TableEmail = &TableInfo{
	Name:       "email",
	ForeignKey: "cert",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
email VARCHAR(128) NOT NULL, -- e.g. 'user@example.com'
PRIMARY KEY (cert, email)
);
CREATE INDEX IF NOT EXISTS {TableName}_email_idx ON {TableName} (email);
{AlterTableForeignKey}
`,
	Upsert: ``,
}

var URITable = &TableInfo{
	Name:       "uri",
	ForeignKey: "cert",
	Create: `CREATE TABLE IF NOT EXISTS {TableName} (
cert BIGINT NOT NULL, -- cert.id
uri VARCHAR(1024) NOT NULL, -- e.g. 'https://www.example.com/path'
PRIMARY KEY (cert, uri)
);
CREATE INDEX IF NOT EXISTS {TableName}_uri_idx ON {TableName} (uri);
{AlterTableForeignKey}
`,
	Upsert: ``,
}
