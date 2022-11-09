package sso_redirector

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	jwtgo "github.com/taliesins/traefik-plugin-oidc/jwt"
)

func signHmac(signingString string, hmacSigningKey interface{}, hmacStrength HmacStrength) (string, error) {
	switch privateKeyType := hmacSigningKey.(type) {
	case *rsa.PrivateKey:
		{
			length := hmacSigningKey.(*rsa.PrivateKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Sign(signingString, hmacSigningKey)
			case 384:
				return jwtgo.SigningMethodRS384.Sign(signingString, hmacSigningKey)
			case 512:
				return jwtgo.SigningMethodRS512.Sign(signingString, hmacSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case *ecdsa.PrivateKey:
		{
			length := hmacSigningKey.(*ecdsa.PrivateKey).Curve.Params().BitSize
			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Sign(signingString, hmacSigningKey)
			case 384:
				return jwtgo.SigningMethodES384.Sign(signingString, hmacSigningKey)
			case 521:
				return jwtgo.SigningMethodES512.Sign(signingString, hmacSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case []byte:
		{
			switch hmacStrength {
			case HmacStrength_256:
				return jwtgo.SigningMethodHS256.Sign(signingString, hmacSigningKey)
			case HmacStrength_384:
				return jwtgo.SigningMethodHS384.Sign(signingString, hmacSigningKey)
			case HmacStrength_512:
				return jwtgo.SigningMethodHS512.Sign(signingString, hmacSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", hmacStrength)
			}
		}
	default:
		return "", fmt.Errorf("unsupported mac signing key type %T", privateKeyType)
	}
}

func verifyHmac(signingString string, signature string, hmacSigningKey interface{}, hmacStrength HmacStrength) error {
	switch publicKeyType := hmacSigningKey.(type) {
	case *rsa.PrivateKey:
		{
			length := hmacSigningKey.(*rsa.PrivateKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 384:
				return jwtgo.SigningMethodRS384.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 512:
				return jwtgo.SigningMethodRS512.Verify(signingString, signature, &publicKeyType.PublicKey)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case *ecdsa.PrivateKey:
		{
			length := hmacSigningKey.(*ecdsa.PrivateKey).Curve.Params().BitSize
			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 384:
				return jwtgo.SigningMethodES384.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 521:
				return jwtgo.SigningMethodES512.Verify(signingString, signature, &publicKeyType.PublicKey)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case *rsa.PublicKey:
		{
			length := hmacSigningKey.(*rsa.PublicKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Verify(signingString, signature, publicKeyType)
			case 384:
				return jwtgo.SigningMethodRS384.Verify(signingString, signature, publicKeyType)
			case 512:
				return jwtgo.SigningMethodRS512.Verify(signingString, signature, publicKeyType)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case *ecdsa.PublicKey:
		{
			length := hmacSigningKey.(*ecdsa.PublicKey).Curve.Params().BitSize
			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Verify(signingString, signature, publicKeyType)
			case 384:
				return jwtgo.SigningMethodES384.Verify(signingString, signature, publicKeyType)
			case 521:
				return jwtgo.SigningMethodES512.Verify(signingString, signature, publicKeyType)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case []byte:
		{
			switch hmacStrength {
			case HmacStrength_256:
				return jwtgo.SigningMethodHS256.Verify(signingString, signature, hmacSigningKey)
			case HmacStrength_384:
				return jwtgo.SigningMethodHS384.Verify(signingString, signature, hmacSigningKey)
			case HmacStrength_512:
				return jwtgo.SigningMethodHS512.Verify(signingString, signature, hmacSigningKey)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", hmacStrength)
			}
		}
	default:
		return fmt.Errorf("unsupported mac signing key type %T", publicKeyType)
	}
}
