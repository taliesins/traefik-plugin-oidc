package test_utils

import (
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
	"os"
	"path/filepath"
)

func GetCertificateFromPath(publicKeyRootPath string, privateKeyRootPath string) (*jwt_certificate.Certificate, error) {
	currentDirectory, err := GetProjectRootPath()
	if err != nil {
		return nil, err
	}

	publicKeyPath := fmt.Sprintf("%s.crt", filepath.Join(currentDirectory, publicKeyRootPath))

	if _, err := os.Stat(publicKeyPath); err == nil {
	} else {
		publicKeyPath = fmt.Sprintf("%s.cert", filepath.Join(currentDirectory, publicKeyRootPath))
	}

	privateKeyPath := fmt.Sprintf("%s.key", filepath.Join(currentDirectory, privateKeyRootPath))

	certificate := &jwt_certificate.Certificate{
		CertFile: jwt_certificate.FileOrContent(publicKeyPath),
		KeyFile:  jwt_certificate.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	return certificate, nil
}

func GetPrivateKeyFromPath(publicKeyRootPath string, privateKeyRootPath string) (interface{}, error) {
	certificate, err := GetCertificateFromPath(publicKeyRootPath, privateKeyRootPath)
	if err != nil {
		return nil, err
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

func GetPublicKeyFromPath(publicKeyRootPath string, privateKeyRootPath string) (interface{}, error) {
	certificate, err := GetCertificateFromPath(publicKeyRootPath, privateKeyRootPath)
	if err != nil {
		return nil, err
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
