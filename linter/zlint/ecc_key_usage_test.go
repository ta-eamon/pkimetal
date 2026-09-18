package zlint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/zmap/zcrypto/x509"
)

func TestECCKeyUsageByCertificateProfile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, time.April, 28, 5, 32, 25, 0, time.UTC)
	issuer := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ECC test issuer"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, tc := range []struct {
		name    string
		profile linter.ProfileId
		isCA    bool
		usage   cryptox509.KeyUsage
		wantErr bool
	}{
		{"TLS CA", linter.TBR_SUBORDINATE_TLSSERVER, true, cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign, false},
		{"EV TLS CA", linter.TEVG_SUBORDINATE_TLSSERVER, true, cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign, false},
		{"subscriber digitalSignature", linter.TBR_LEAF_TLSSERVER_DV, false, cryptox509.KeyUsageDigitalSignature, false},
		{"subscriber missing digitalSignature", linter.TBR_LEAF_TLSSERVER_DV, false, cryptox509.KeyUsageKeyAgreement, true},
		{"subscriber prohibited cRLSign", linter.TBR_LEAF_TLSSERVER_DV, false, cryptox509.KeyUsageDigitalSignature | cryptox509.KeyUsageCRLSign, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &cryptox509.Certificate{
				SerialNumber:          big.NewInt(2),
				Subject:               pkix.Name{CommonName: "ECC test subject"},
				NotBefore:             notBefore,
				NotAfter:              notBefore.AddDate(0, 1, 0),
				KeyUsage:              tc.usage,
				ExtKeyUsage:           []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  tc.isCA,
			}
			der, err := cryptox509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			results := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
				Cert:      cert,
				ProfileId: tc.profile,
			})
			var hasError bool
			for _, finding := range results {
				if finding.Code == "e_cabf_ecc_allowed_key_usages" && finding.Severity == linter.SEVERITY_ERROR {
					hasError = true
				}
			}
			if hasError != tc.wantErr {
				t.Errorf("e_cabf_ecc_allowed_key_usages error = %t, want %t", hasError, tc.wantErr)
			}
		})
	}
}
