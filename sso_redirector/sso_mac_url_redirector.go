package sso_redirector

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	jwtgo "github.com/taliesins/traefik-plugin-oidc/jwt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var CallbackPath = "/oauth2/callback"
var RedirectorPath = "/oauth2/redirector" //TODO: did this value auto refactor to the wrong name
var RobotsPath = "/robots.txt"

var RedirectUriQuerystringParameterName = "redirect_uri"
var NonceQuerystringParameterName = "nonce"
var IssuedAtQuerystringParameterName = "iat"
var HashQuerystringParameterName = "hash"

var IdTokenBookmarkParameterName = "id_token"
var StateBookmarkParameterName = "state"

func CloneUrl(r *http.Request) *url.URL {
	clonedUrl := &url.URL{
		Scheme:   r.URL.Scheme,
		Opaque:   r.URL.Opaque,
		User:     r.URL.User,
		Host:     r.URL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	if clonedUrl.Host == "" {
		clonedUrl.Host = r.Host
	}

	if clonedUrl.Scheme == "" {
		if r.TLS != nil {
			clonedUrl.Scheme = "https"
		} else {
			clonedUrl.Scheme = "http"
		}
	}

	return clonedUrl
}

func AddMacHashToUrl(url *url.URL, macSigningKey interface{}, macStrength MacStrength) error {
	hash, err := signMac(url.String(), macSigningKey, macStrength)
	if err != nil {
		return err
	}
	q := url.Query()
	q.Set(HashQuerystringParameterName, hash)
	url.RawQuery = q.Encode()
	return nil
}

func VerifyAndStripMacHashFromUrl(url *url.URL, macSigningKey interface{}, macStrength MacStrength) error {
	query := url.Query()

	signature := query.Get(HashQuerystringParameterName)
	if signature == "" {
		return fmt.Errorf("no %s querystring in uri", HashQuerystringParameterName)
	}

	q := url.Query()
	q.Del(HashQuerystringParameterName)
	url.RawQuery = q.Encode()

	return verifyMac(url.String(), signature, macSigningKey, macStrength)
}

// var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
func GetRedirectorUrl(r *http.Request, macSigningKey interface{}, macStrength MacStrength, nonce string, issuedAt string) (*url.URL, error) {
	clonedUrl := CloneUrl(r)
	redirectUrl := clonedUrl.String()
	clonedUrl.Path = RedirectorPath

	q := clonedUrl.Query()
	q.Set(RedirectUriQuerystringParameterName, redirectUrl)
	q.Set(NonceQuerystringParameterName, nonce)
	q.Set(IssuedAtQuerystringParameterName, issuedAt)
	clonedUrl.RawQuery = q.Encode()

	err := AddMacHashToUrl(clonedUrl, macSigningKey, macStrength)
	if err != nil {
		return nil, err
	}

	return clonedUrl, nil
}

func GetRedirectUrl(r *http.Request, macSigningKey interface{}, macStrength MacStrength, allowedClockSkew time.Duration) (*url.URL, error) {
	clonedUrl := CloneUrl(r)

	err := VerifyAndStripMacHashFromUrl(clonedUrl, macSigningKey, macStrength)
	if err != nil {
		return nil, err
	}

	query := r.URL.Query()

	redirectUriQueryStringParameterValue := query.Get(RedirectUriQuerystringParameterName)
	if redirectUriQueryStringParameterValue == "" {
		return nil, fmt.Errorf("no %s querystring in uri", RedirectUriQuerystringParameterName)
	}

	redirectUri, err := url.Parse(redirectUriQueryStringParameterValue)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid uri", redirectUri)
	}

	nonce := query.Get(NonceQuerystringParameterName)
	if nonce == "" {
		return nil, fmt.Errorf("no %s querystring in uri", NonceQuerystringParameterName)
	}

	issuedAtQueryStringParameterValue := query.Get(IssuedAtQuerystringParameterName)
	if issuedAtQueryStringParameterValue == "" {
		return nil, fmt.Errorf("no %s querystring in uri", IssuedAtQuerystringParameterName)
	}

	issuedAtUnixEpochSeconds, err := strconv.ParseInt(issuedAtQueryStringParameterValue, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to convert iat %v into unix epoch seconds", issuedAtUnixEpochSeconds)
	}

	iat := time.Unix(issuedAtUnixEpochSeconds, 0)
	now := time.Now().UTC()
	startWindow := iat.Add(-1 * allowedClockSkew)
	endWindow := iat.Add(allowedClockSkew)

	if endWindow.Before(now) {
		return nil, fmt.Errorf("iat has passed the valididty window")
	}

	if now.Before(startWindow) {
		return nil, fmt.Errorf("iat has not begun the valididty window")
	}

	return redirectUri, nil
}

func signMac(signingString string, macSigningKey interface{}, macStrength MacStrength) (string, error) {
	switch privateKeyType := macSigningKey.(type) {
	case *rsa.PrivateKey:
		{
			var rsaMacSigningKey *rsa.PrivateKey
			rsaMacSigningKey = macSigningKey.(*rsa.PrivateKey)

			length := rsaMacSigningKey.N.BitLen() / 8

			switch length {
			case 256:
				signed, err := jwtgo.SigningMethodRS256.Sign(signingString, rsaMacSigningKey)
				return signed, err
			case 384:
				return jwtgo.SigningMethodRS384.Sign(signingString, macSigningKey)
			case 512:
				return jwtgo.SigningMethodRS512.Sign(signingString, macSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case *ecdsa.PrivateKey:
		{
			fmt.Printf("start sign ecdsa\n")

			length := macSigningKey.(*ecdsa.PrivateKey).Curve.Params().BitSize

			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Sign(signingString, macSigningKey)
			case 384:
				return jwtgo.SigningMethodES384.Sign(signingString, macSigningKey)
			case 521:
				return jwtgo.SigningMethodES512.Sign(signingString, macSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", length)
			}
		}
	case []byte:
		{
			fmt.Printf("start sign byte\n")
			switch macStrength {
			case MacStrength_256:
				return jwtgo.SigningMethodHS256.Sign(signingString, macSigningKey)
			case MacStrength_384:
				return jwtgo.SigningMethodHS384.Sign(signingString, macSigningKey)
			case MacStrength_512:
				return jwtgo.SigningMethodHS512.Sign(signingString, macSigningKey)
			default:
				return "", fmt.Errorf("unsupported mac signing method strength %T", macStrength)
			}
		}
	default:
		fmt.Printf("start sign default\n")
		return "", fmt.Errorf("unsupported mac signing key type %T", privateKeyType)
	}
}

func verifyMac(signingString string, signature string, macSigningKey interface{}, macStrength MacStrength) error {
	switch publicKeyType := macSigningKey.(type) {
	case *rsa.PrivateKey:
		{
			length := macSigningKey.(*rsa.PrivateKey).N.BitLen() / 8
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
			length := macSigningKey.(*ecdsa.PrivateKey).Curve.Params().BitSize

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
			length := macSigningKey.(*rsa.PublicKey).N.BitLen() / 8
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
			length := macSigningKey.(*ecdsa.PublicKey).Curve.Params().BitSize

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
			switch macStrength {
			case MacStrength_256:
				return jwtgo.SigningMethodHS256.Verify(signingString, signature, macSigningKey)
			case MacStrength_384:
				return jwtgo.SigningMethodHS384.Verify(signingString, signature, macSigningKey)
			case MacStrength_512:
				return jwtgo.SigningMethodHS512.Verify(signingString, signature, macSigningKey)
			default:
				return fmt.Errorf("unsupported mac signing method strength %T", macStrength)
			}
		}
	default:
		return fmt.Errorf("unsupported mac signing key type %T", publicKeyType)
	}
}
