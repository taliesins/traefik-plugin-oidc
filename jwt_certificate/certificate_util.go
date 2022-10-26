package jwt_certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	jwtgo "github.com/taliesins/traefik-plugin-oidc/jwt"
	"net/url"
	"reflect"
)

func GetPrivateKey(privateKeyData []byte) (privateKey interface{}, err error) {
	privateKeyBlockBytes := privateKeyData

	privateKeyBlock, rest := pem.Decode(privateKeyData)
	if !(privateKeyBlock == nil || len(rest) > 0) {
		switch privateKeyBlock.Type {
		case "PRIVATE KEY":
			privateKeyBlockBytes = privateKeyBlock.Bytes
		case "RSA PRIVATE KEY":
			privateKeyBlockBytes = privateKeyBlock.Bytes
		case "EC PRIVATE KEY":
			privateKeyBlockBytes = privateKeyBlock.Bytes
		default:
			return nil, fmt.Errorf("Unsupported private key type %q", privateKeyBlock.Type)
		}
	} else {
		privateKeyBlockBytes, err = x509.MarshalPKCS8PrivateKey(privateKeyData)
		if err != nil {
			privateKeyBlockBytes = privateKeyData
		}
	}

	privateKey, errParsePKCS8PrivateKey := x509.ParsePKCS8PrivateKey(privateKeyBlockBytes)
	if errParsePKCS8PrivateKey == nil {
		return privateKey, nil
	}

	privateKey, errParsePKCS1PrivateKey := x509.ParsePKCS1PrivateKey(privateKeyBlockBytes)
	if errParsePKCS1PrivateKey == nil {
		return privateKey, nil
	}

	privateKey, errParseECPrivateKey := x509.ParseECPrivateKey(privateKeyBlockBytes)
	if errParseECPrivateKey == nil {
		return privateKey, nil
	}

	return nil, errParsePKCS8PrivateKey
}

func GetPublicKey(publicKeyData []byte) (publicKey interface{}, err error) {
	publicKeyBlockBytes := publicKeyData
	publicKeyBlock, rest := pem.Decode(publicKeyData)
	if !(publicKeyBlock == nil || len(rest) > 0) {
		switch publicKeyBlock.Type {
		case "CERTIFICATE":
			{
				publicKeyBlockBytes = publicKeyBlock.Bytes
			}
		case "PUBLIC KEY":
			{
				publicKeyBlockBytes = publicKeyBlock.Bytes
			}
		default:
			return nil, fmt.Errorf("Unsupported private key type %q", publicKeyBlock.Type)
		}
	} else {
		publicKeyBlockBytes, err = x509.MarshalPKIXPublicKey(publicKeyData)
		if err != nil {
			publicKeyBlockBytes = publicKeyData
		}
	}

	publicKey, errParsePKIXPublicKey := x509.ParsePKIXPublicKey(publicKeyBlockBytes)
	if errParsePKIXPublicKey == nil {
		return publicKey, nil
	}

	publicKey, errParsePKCS1PublicKey := x509.ParsePKCS1PublicKey(publicKeyBlockBytes)
	if errParsePKCS1PublicKey == nil {
		return publicKey, nil
	}

	cert, err := x509.ParseCertificate(publicKeyBlockBytes)
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

// JSONWebKey represents a public or private key in JWK format.
type JSONWebKey struct {
	// Cryptographic key, can be a symmetric or asymmetric key.
	Key interface{}
	// Key identifier, parsed from `kid` header.
	KeyID string
	// Key algorithm, parsed from `alg` header.
	Algorithm string
	// Key use, parsed from `use` header.
	Use string

	// X.509 certificate chain, parsed from `x5c` header.
	Certificates []*x509.Certificate
	// X.509 certificate URL, parsed from `x5u` header.
	CertificatesURL *url.URL
	// X.509 certificate thumbprint (SHA-1), parsed from `x5t` header.
	CertificateThumbprintSHA1 []byte
	// X.509 certificate thumbprint (SHA-256), parsed from `x5t#S256` header.
	CertificateThumbprintSHA256 []byte
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// Valid checks that the key contains the expected parameters.
func (k *JSONWebKey) Valid() bool {
	if k.Key == nil {
		return false
	}
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.X == nil || key.Y == nil {
			return false
		}
	case *ecdsa.PrivateKey:
		if key.Curve == nil || key.X == nil || key.Y == nil || key.D == nil {
			return false
		}
	case *rsa.PublicKey:
		if key.N == nil || key.E == 0 {
			return false
		}
	case *rsa.PrivateKey:
		if key.N == nil || key.E == 0 || key.D == nil || len(key.Primes) < 2 {
			return false
		}
	case ed25519.PublicKey:
		if len(key) != 32 {
			return false
		}
	case ed25519.PrivateKey:
		if len(key) != 64 {
			return false
		}
	default:
		return false
	}
	return true
}

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken struct {
	payload           func(k interface{}) ([]byte, error)
	unverifiedPayload func() []byte
	Headers           []Header
}

// Header represents the read-only JOSE header for JWE/JWS objects.
type Header struct {
	KeyID      string
	JSONWebKey *JSONWebKey
	Algorithm  string
	Nonce      string

	// Unverified certificate chain parsed from x5c header.
	certificates []*x509.Certificate

	// Any headers not recognised above get unmarshalled
	// from JSON in a generic manner and placed in this map.
	ExtraHeaders map[HeaderKey]interface{}
}

type HeaderKey string
