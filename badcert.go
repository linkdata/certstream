package certstream

import (
	"crypto/sha256"
	"encoding/asn1"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/jackc/pgx/v5"
)

const insertBadCertIdents = `INSERT /* CERTDB_badcert_idents */ INTO CERTDB_ident (organization, province, country)
SELECT organization, province, country
FROM (VALUES ($1::text, $2::text, $3::text), ($4::text, $5::text, $6::text)) AS identities(organization, province, country)
ORDER BY organization, province, country
ON CONFLICT (organization, province, country) DO NOTHING;`

const insertBadCert = `INSERT /* CERTDB_badcert_insert */ INTO CERTDB_badcert
(seen, logindex, stream, commonname, subject, issuer, sha256, rawcert)
VALUES (
  $1::timestamptz AT TIME ZONE 'UTC', $2, $3, $4,
  (SELECT id FROM CERTDB_ident WHERE organization = $5 AND province = $6 AND country = $7),
  (SELECT id FROM CERTDB_ident WHERE organization = $8 AND province = $9 AND country = $10),
  $11, $12
)
ON CONFLICT (stream, logindex) DO NOTHING;`

type badCertMetadata struct {
	commonName string
	subject    [3]string
	issuer     [3]string
}

func parseBadCertMetadata(raw []byte) (metadata badCertMetadata) {
	var cert *x509.Certificate
	var outer, first asn1.RawValue
	// The outer signature field may be invalid while the signed TBS remains readable.
	if _, err := asn1.Unmarshal(raw, &outer); err == nil && outer.Class == 0 && outer.Tag == asn1.TagSequence {
		if _, err = asn1.Unmarshal(outer.Bytes, &first); err == nil && first.Class == 0 && first.Tag == asn1.TagSequence {
			cert, _ = x509.ParseTBSCertificate(first.FullBytes)
		}
	}
	if cert == nil {
		cert, _ = x509.ParseTBSCertificate(raw)
	}
	if cert != nil {
		metadata.commonName = badCertText((&Certificate{Certificate: cert}).GetCommonName())
		metadata.subject = [3]string{
			badCertText(strings.Join(cert.Subject.Organization, ",")),
			badCertText(strings.Join(cert.Subject.Province, ",")),
			badCertText(strings.Join(cert.Subject.Country, ",")),
		}
		metadata.issuer = [3]string{
			badCertText(strings.Join(cert.Issuer.Organization, ",")),
			badCertText(strings.Join(cert.Issuer.Province, ",")),
			badCertText(strings.Join(cert.Issuer.Country, ",")),
		}
	}
	return
}

func badCertText(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
}

func (cdb *PgDB) queueBadCert(batch *pgx.Batch, le *LogEntry, seen time.Time) {
	metadata := parseBadCertMetadata(le.rawCert)
	batch.Queue(cdb.Pfx(insertBadCertIdents),
		metadata.subject[0], metadata.subject[1], metadata.subject[2],
		metadata.issuer[0], metadata.issuer[1], metadata.issuer[2])
	hash := sha256.Sum256(le.rawCert)
	batch.Queue(cdb.Pfx(insertBadCert), seen, le.LogIndex, le.LogStream.Id, metadata.commonName,
		metadata.subject[0], metadata.subject[1], metadata.subject[2],
		metadata.issuer[0], metadata.issuer[1], metadata.issuer[2],
		hash[:], le.rawCert)
}
