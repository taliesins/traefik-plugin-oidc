package sso_redirector

import (
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
	"net/url"
	"os"
	"path"
	"runtime"
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

func getPrivateKeyForTest(relativePathToCert string) (interface{}, error) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), relativePathToCert)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	privateKeyPemData, err := certificate.KeyFile.Read()
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt_certificate.GetPrivateKey(privateKeyPemData)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getPublicKeyForTest(relativePathToCert string) (interface{}, error) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), relativePathToCert)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	publicKeyPemData, err := certificate.CertFile.Read()
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt_certificate.GetPublicKey(publicKeyPemData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func TestAddHashAndRemoveHashUsingPrivateKeyAndPublicKeySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	privateKey, err := getPrivateKeyForTest("../integration/fixtures/https/snitest.com")
	macStrength := MacStrength_256

	err = AddMacHashToUrl(testUrl, privateKey, macStrength)
	if err != nil {
		panic(err)
	}
	publicKey, err := getPublicKeyForTest("../integration/fixtures/https/snitest.com")
	if err != nil {
		panic(err)
	}
	err = VerifyAndStripMacHashFromUrl(testUrl, publicKey, macStrength)
	if err != nil {
		panic(err)
	}
}

func TestAddHashAndRemoveHashUsingPrivateKeyOnlySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	privateKey, err := getPrivateKeyForTest("../integration/fixtures/https/snitest.com")
	macStrength := MacStrength_256

	err = AddMacHashToUrl(testUrl, privateKey, macStrength)
	if err != nil {
		panic(err)
	}
	err = VerifyAndStripMacHashFromUrl(testUrl, privateKey, macStrength)
	if err != nil {
		panic(err)
	}
}
