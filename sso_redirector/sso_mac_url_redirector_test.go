package sso_redirector

import (
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/assert"
	"github.com/taliesins/traefik-plugin-oidc/test_utils"
	"net/url"
	"testing"
)

func TestAddHashAndRemoveHashUsingClientSecretSuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	key := []byte("mySecret")
	macStrength := MacStrength_256

	err = AddMacHashToUrl(testUrl, key, macStrength)
	if err != nil {
		panic(err)
	}

	err = VerifyAndStripMacHashFromUrl(testUrl, key, macStrength)
	if err != nil {
		panic(err)
	}
}

func TestAddHashAndRemoveHashUsingPrivateKeyAndPublicKeySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	assert.NoError(t, err)

	privateKey, err := test_utils.GetPrivateKeyFromPath("integration/fixtures/https/snitest.com", "integration/fixtures/https/snitest.com")
	macStrength := MacStrength_256

	err = AddMacHashToUrl(testUrl, privateKey, macStrength)
	assert.NoError(t, err)
	publicKey, err := test_utils.GetPublicKeyFromPath("integration/fixtures/https/snitest.com", "integration/fixtures/https/snitest.com")
	assert.NoError(t, err)
	err = VerifyAndStripMacHashFromUrl(testUrl, publicKey, macStrength)
	assert.NoError(t, err)
}

func TestAddHashAndRemoveHashUsingPrivateKeyOnlySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	assert.NoError(t, err)

	privateKey, err := test_utils.GetPrivateKeyFromPath("integration/fixtures/https/snitest.com", "integration/fixtures/https/snitest.com")
	assert.NoError(t, err)
	fmt.Printf("got privateKey no error\n")

	macStrength := MacStrength_256

	err = AddMacHashToUrl(testUrl, privateKey, macStrength)
	assert.NoError(t, err)
	fmt.Printf("got AddMacHashToUrl no error\n")

	err = VerifyAndStripMacHashFromUrl(testUrl, privateKey, macStrength)
	assert.NoError(t, err)

	fmt.Printf("got VerifyAndStripMacHashFromUrl no error\n")
}
