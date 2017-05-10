package trustpinning

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
	"github.com/stretchr/testify/require"
)

func TestWildcardMatch(t *testing.T) {
	testCerts := map[string][]string{
		"docker.io/library/ubuntu": {"abc"},
		"docker.io/endophage/b*":   {"def"},
		"docker.io/endophage/*":    {"xyz"},
	}

	// wildcardMatch should ONLY match wildcarded names even if a specific
	// match is present
	res, ok := wildcardMatch("docker.io/library/ubuntu", testCerts)
	require.Nil(t, res)
	require.False(t, ok)

	// wildcard match should match on segment boundaries
	res, ok = wildcardMatch("docker.io/endophage/foo", testCerts)
	require.Len(t, res, 1)
	require.Equal(t, "xyz", res[0])
	require.True(t, ok)

	// wildcardMatch should also match between segment boundaries, and take
	// the longest match it finds as the ONLY match (i.e. there is no merging
	// of key IDs when there are multiple matches).
	res, ok = wildcardMatch("docker.io/endophage/bar", testCerts)
	require.Len(t, res, 1)
	require.Equal(t, "def", res[0])
	require.True(t, ok)
}

func TestCAPin(t *testing.T) {
	gun := "docker.io/trust"
	//docker.io/*
	certPEM := ` 
-----BEGIN CERTIFICATE-----
MIIB7DCCAZKgAwIBAgIJALnp3vBMWI5sMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTcwNTA5MjA0MjI5WhcNMTcwNjA4MjA0MjI5WjB7MQsw
CQYDVQQGEwJVUzERMA8GA1UECAwISWxsaW5vaXMxEDAOBgNVBAcMB0NoaWNhZ28x
DzANBgNVBAoMBkRvY2tlcjEgMB4GA1UECwwXQ2hpZWYgVGVjaG5vbG9neSBPZmZp
Y2UxFDASBgNVBAMMC2RvY2tlci5pby8qMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEuRYp3Da3fQI8thP7a8oTlqE30zp8gkhpN1Llq6+NfwEyyBJ92jtkKytPETF5
4Xyml0wlWwCUFTnIaxf2YyPxD6M1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQM
MAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAPtM
Rs4GRvpmmzdECpdat9eHx2G9NRBzpDsJx0wojW4HAiB5JQq4S7rqklxtn/crZwED
AZzaL8Z0XP0vJ8ELK7cocA==
-----END CERTIFICATE-----`
	rootPEM := `
-----BEGIN CERTIFICATE-----
MIIB0TCCAXegAwIBAgIJAP/ND7QR4/J9MAoGCCqGSM49BAMDMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTcwNDI4MjEyMjQ0WhcNMjcwNDI2MjEyMjQ0WjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuRYp
3Da3fQI8thP7a8oTlqE30zp8gkhpN1Llq6+NfwEyyBJ92jtkKytPETF54Xyml0wl
WwCUFTnIaxf2YyPxD6NQME4wHQYDVR0OBBYEFDEnUBGTR7Datfclq/8a0EOr6d0R
MB8GA1UdIwQYMBaAFDEnUBGTR7Datfclq/8a0EOr6d0RMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwMDSAAwRQIgKQ5Obm/e+tOYZHgCWFurk1G6KQyzhldJLd+hYizi
5rQCIQDTZEITcd3NLZvSJxyL9m4SzXaIU5pRBJwJ6LevUVZzfQ==
-----END CERTIFICATE-----`

	const notMatchingRootPEM = `
-----BEGIN CERTIFICATE-----
MIIBdzCCAR6gAwIBAgIRANMx80QkI0KQTKFL+rg1HXgwCgYIKoZIzj0EAwIwIjEg
MB4GA1UEAxMXbW90b3JvbGFzb2x1dGlvbnMuY29tLyowHhcNMTcwNDI3MDAwNDUw
WhcNMjcwNDI1MDAwNDUwWjAiMSAwHgYDVQQDExdtb3Rvcm9sYXNvbHV0aW9ucy5j
b20vKjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFRLWjemscL5XVx/OB2Ca+BD
q2MSSkG4bhy1qv++HxLsA/kKlKM8S5fqks57BZRY2qNJ+9f892QZTdov2p9Xx3+j
NTAzMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMB
Af8EAjAAMAoGCCqGSM49BAMCA0cAMEQCIE6hcVWy1KguR/RE0vlzbRQBQIfaX9/Y
WPqb8ro01YRSAiB6R01leLMhFslBiwMF/QmkKv7FjJSO7tAv29ESqommDA==
-----END CERTIFICATE-----`

	//create temp dir
	tempDir, err := ioutil.TempDir("", "trustpin")
	require.NoError(t, err)

	// write CA cert and leaf cert to file
	CAFN := filepath.Join(tempDir, "leaf.crt")
	CAFile := filepath.Join(tempDir, "ca.crt")
	nonMatchingCAFN := filepath.Join(tempDir, "nonMatching.crt")
	err = ioutil.WriteFile(CAFN, []byte(certPEM), 0644)
	require.NoError(t, err)
	err = ioutil.WriteFile(CAFile, []byte(rootPEM), 0644)
	require.NoError(t, err)
	err = ioutil.WriteFile(nonMatchingCAFN, []byte(rootPEM), 0644)
	require.NoError(t, err)

	// init trust pinning config
	trustConfig := TrustPinConfig{
		CA:          map[string]string{"docker.io/": CAFile},
		DisableTOFU: true,
	}

	trustChecker, err := NewTrustPinChecker(trustConfig, data.GUN(gun), true)
	require.NoError(t, err)

	leafCert, err := utils.LoadCertBundleFromFile(CAFN)
	require.NoError(t, err, "could not load root cert from CA path")

	// perform check
	ok := trustChecker(leafCert[0], nil)
	require.True(t, ok, "expected cert chain to be valid, but got invalid")

}
