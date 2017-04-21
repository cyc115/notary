package cryptoservice

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"strings"

	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
)

// GenerateCertificate generates an X509 Certificate from a template, given a GUN and validity interval
func GenerateCertificate(rootKey data.PrivateKey, gun data.GUN, startTime, endTime time.Time) (*x509.Certificate, error) {
	signer := rootKey.CryptoSigner()
	if signer == nil {
		return nil, fmt.Errorf("key type not supported for Certificate generation: %s", rootKey.Algorithm())
	}

	return generateCertificate(signer, gun, startTime, endTime)
}

func generateCertificate(signer crypto.Signer, gun data.GUN, startTime, endTime time.Time) (*x509.Certificate, error) {

	//remove the last segment of repo name separated by `/` and append a wildcard *
	wildCardedGUN := gun.String()[0:strings.LastIndex(gun.String(), `/`)+1] + "*"

	template, err := utils.NewCertificate(wildCardedGUN, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create the certificate template for: %s (%v)", wildCardedGUN, err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create the certificate for: %s (%v)", wildCardedGUN, err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the certificate for key: %s (%v)", wildCardedGUN, err)
	}

	return cert, nil
}
