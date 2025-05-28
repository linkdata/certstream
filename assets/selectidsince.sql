SELECT id, subject, issuer, notbefore, since FROM CERTDB_cert
    WHERE commonname=$1
    AND subject=(SELECT id FROM CERTDB_ident WHERE organization=$2 AND province=$3 AND country=$4)
    AND issuer=(SELECT id FROM CERTDB_ident WHERE organization=$5 AND province=$6 AND country=$7)
    AND notbefore<=$8 AND notafter>=$8
    ORDER BY notbefore DESC LIMIT 1;