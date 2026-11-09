package certstream

import (
	"crypto/sha256"
	"crypto/x509/pkix"
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
	tbs := raw
	var outer, first asn1.RawValue
	// The outer signature field may be invalid while the signed TBS remains readable.
	if _, err := asn1.Unmarshal(raw, &outer); err == nil && outer.Class == 0 && outer.Tag == asn1.TagSequence {
		if _, err = asn1.Unmarshal(outer.Bytes, &first); err == nil && first.Class == 0 && first.Tag == asn1.TagSequence {
			tbs = first.FullBytes
		}
	}
	cert, _ := x509.ParseTBSCertificate(tbs)
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
	} else {
		metadata = parseBadCertNames(tbs)
	}
	return
}

func parseBadCertNames(tbs []byte) (metadata badCertMetadata) {
	var fields struct {
		Version   int `asn1:"optional,explicit,default:0,tag:0"`
		Serial    asn1.RawValue
		Signature asn1.RawValue
		Issuer    asn1.RawValue
		Validity  asn1.RawValue
		Subject   asn1.RawValue
	}
	if _, err := asn1.Unmarshal(tbs, &fields); err == nil &&
		fields.Serial.Class == 0 && fields.Serial.Tag == asn1.TagInteger &&
		fields.Signature.Class == 0 && fields.Signature.Tag == asn1.TagSequence &&
		fields.Validity.Class == 0 && fields.Validity.Tag == asn1.TagSequence {
		_, metadata.issuer = parseBadCertName(fields.Issuer)
		metadata.commonName, metadata.subject = parseBadCertName(fields.Subject)
	}
	return
}

func parseBadCertName(raw asn1.RawValue) (commonName string, identity [3]string) {
	if raw.Class != 0 || raw.Tag != asn1.TagSequence {
		return
	}
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw.FullBytes, &rdn); err == nil && len(rest) == 0 {
		var name pkix.Name
		name.FillFromRDNSequence(&rdn)
		commonName = badCertText(name.CommonName)
		identity = [3]string{
			badCertText(strings.Join(name.Organization, ",")),
			badCertText(strings.Join(name.Province, ",")),
			badCertText(strings.Join(name.Country, ",")),
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
