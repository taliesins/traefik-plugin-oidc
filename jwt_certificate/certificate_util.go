package jwt_certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	jwtgo "github.com/golang-jwt/jwt/v4"
	"reflect"
)

func GetPrivateKey(privateKeyData []byte) (interface{}, error) {
	privateKey, errParsePKCS8PrivateKey := x509.ParsePKCS8PrivateKey(privateKeyData)
	if errParsePKCS8PrivateKey == nil {
		return privateKey, nil
	}

	privateKey, errParsePKCS1PrivateKey := x509.ParsePKCS1PrivateKey(privateKeyData)
	if errParsePKCS1PrivateKey == nil {
		return privateKey, nil
	}

	privateKey, errParseECPrivateKey := x509.ParseECPrivateKey(privateKeyData)
	if errParseECPrivateKey == nil {
		return privateKey, nil
	}

	return nil, errParsePKCS8PrivateKey
}

func GetPublicKey(publicKeyData []byte) (interface{}, error) {
	publicKey, errParsePKIXPublicKey := x509.ParsePKIXPublicKey(publicKeyData)
	if errParsePKIXPublicKey == nil {
		return publicKey, nil
	}

	publicKey, errParsePKCS1PublicKey := x509.ParsePKCS1PublicKey(publicKeyData)
	if errParsePKCS1PublicKey == nil {
		return publicKey, nil
	}

	cert, err := x509.ParseCertificate(publicKeyData)
	if err == nil {
		return cert.PublicKey, nil
	}

	return nil, errParsePKIXPublicKey
}

func GetJwtParametersFromPublicKey(publicKey interface{}) (string, string, string, x509.SignatureAlgorithm, error) {
	var keyType string
	var algorithm string
	var curve string
	var signatureAlgorithm x509.SignatureAlgorithm
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		length := publicKey.(*rsa.PublicKey).N.BitLen() / 8

		/*
			// https://www.scottbrady91.com/jose/jwts-which-signing-algorithm-should-i-use

			//Deterministic
			switch length {
			case 256:
				signatureAlgorithm = x509.SHA256WithRSA
				algorithm = jwtgo.SigningMethodRS256.Alg()
			case 384:
				signatureAlgorithm = x509.SHA384WithRSA
				algorithm = jwtgo.SigningMethodRS384.Alg()
			case 512:
				signatureAlgorithm = x509.SHA512WithRSA
				algorithm = jwtgo.SigningMethodRS512.Alg()
			}
		*/

		//Probabilistic
		switch length {
		case 256:
			signatureAlgorithm = x509.SHA256WithRSAPSS
			algorithm = jwtgo.SigningMethodPS256.Alg()
		case 384:
			signatureAlgorithm = x509.SHA384WithRSAPSS
			algorithm = jwtgo.SigningMethodPS384.Alg()
		case 512:
			signatureAlgorithm = x509.SHA512WithRSAPSS
			algorithm = jwtgo.SigningMethodPS512.Alg()
		}

		keyType = "RSA"
	case *ecdsa.PublicKey:
		length := publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize

		switch length {
		case 256:
			signatureAlgorithm = x509.ECDSAWithSHA256
			algorithm = jwtgo.SigningMethodES256.Alg()
		case 384:
			signatureAlgorithm = x509.ECDSAWithSHA384
			algorithm = jwtgo.SigningMethodES384.Alg()
		case 521:
			signatureAlgorithm = x509.ECDSAWithSHA512
			algorithm = jwtgo.SigningMethodES512.Alg()
		}

		keyType = "EC"
	/*
		case *dsa.PublicKey:
			length := publicKey.(*dsa.PublicKey).P.BitLen()
			signatureAlgorithm = x509.DSAWithSHA256
			algorithm = not supported
			keyType = "DSA"
	*/
	case *ed25519.PublicKey:
		curve = "Ed25519"
		signatureAlgorithm = x509.PureEd25519
		algorithm = (&jwtgo.SigningMethodEd25519{}).Alg()
		keyType = "OKP"
	default:
		return "", "", "", x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown private key type '%s'", reflect.TypeOf(key))
	}
	return keyType, algorithm, curve, signatureAlgorithm, nil
}
