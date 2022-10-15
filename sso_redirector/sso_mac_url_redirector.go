package sso_redirector

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	jwtgo "github.com/golang-jwt/jwt/v4"
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

func AddMacHashToUrl(url *url.URL, key interface{}, macStrength MacStrength) error {
	hash, err := signMac(url.String(), key, macStrength)
	if err != nil {
		return err
	}
	q := url.Query()
	q.Set(HashQuerystringParameterName, hash)
	url.RawQuery = q.Encode()
	return nil
}

func VerifyAndStripMacHashFromUrl(url *url.URL, key interface{}, macStrength MacStrength) error {
	query := url.Query()

	signature := query.Get(HashQuerystringParameterName)
	if signature == "" {
		return fmt.Errorf("No %s querystring in uri", HashQuerystringParameterName)
	}

	q := url.Query()
	q.Del(HashQuerystringParameterName)
	url.RawQuery = q.Encode()

	return verifyMac(url.String(), signature, key, macStrength)
}

// var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
func GetRedirectorUrl(r *http.Request, key interface{}, macStrength MacStrength, nonce string, issuedAt string) (*url.URL, error) {
	clonedUrl := CloneUrl(r)
	redirectUrl := clonedUrl.String()
	clonedUrl.Path = RedirectorPath

	q := clonedUrl.Query()
	q.Set(RedirectUriQuerystringParameterName, redirectUrl)
	q.Set(NonceQuerystringParameterName, nonce)
	q.Set(IssuedAtQuerystringParameterName, issuedAt)
	clonedUrl.RawQuery = q.Encode()

	err := AddMacHashToUrl(clonedUrl, key, macStrength)
	if err != nil {
		return nil, err
	}

	return clonedUrl, nil
}

func GetRedirectUrl(r *http.Request, key interface{}, macStrength MacStrength, allowedClockSkew time.Duration) (*url.URL, error) {
	clonedUrl := CloneUrl(r)

	err := VerifyAndStripMacHashFromUrl(clonedUrl, key, macStrength)
	if err != nil {
		return nil, err
	}

	query := r.URL.Query()

	redirectUriQueryStringParameterValue := query.Get(RedirectUriQuerystringParameterName)
	if redirectUriQueryStringParameterValue == "" {
		return nil, fmt.Errorf("No %s querystring in uri", RedirectUriQuerystringParameterName)
	}

	redirectUri, err := url.Parse(redirectUriQueryStringParameterValue)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid uri", redirectUri)
	}

	nonce := query.Get(NonceQuerystringParameterName)
	if nonce == "" {
		return nil, fmt.Errorf("No %s querystring in uri", NonceQuerystringParameterName)
	}

	issuedAtQueryStringParameterValue := query.Get(IssuedAtQuerystringParameterName)
	if issuedAtQueryStringParameterValue == "" {
		return nil, fmt.Errorf("No %s querystring in uri", IssuedAtQuerystringParameterName)
	}

	issuedAtUnixEpochSeconds, err := strconv.ParseInt(issuedAtQueryStringParameterValue, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Unable to convert iat %s into unix epoch seconds", issuedAtUnixEpochSeconds)
	}

	iat := time.Unix(issuedAtUnixEpochSeconds, 0)
	now := time.Now().UTC()
	startWindow := iat.Add(-1 * allowedClockSkew)
	endWindow := iat.Add(allowedClockSkew)

	if endWindow.Before(now) {
		return nil, fmt.Errorf("Iat has passed the valididty window")
	}

	if now.Before(startWindow) {
		return nil, fmt.Errorf("Iat has not begun the valididty window")
	}

	return redirectUri, nil
}

func signMac(signingString string, key interface{}, macStrength MacStrength) (string, error) {
	switch privateKeyType := key.(type) {
	case *rsa.PrivateKey:
		{
			length := key.(*rsa.PrivateKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Sign(signingString, privateKeyType)
			case 384:
				return jwtgo.SigningMethodRS384.Sign(signingString, privateKeyType)
			case 512:
				return jwtgo.SigningMethodRS512.Sign(signingString, privateKeyType)
			default:
				return "", fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case *ecdsa.PrivateKey:
		{
			length := key.(*ecdsa.PrivateKey).Curve.Params().BitSize

			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Sign(signingString, privateKeyType)
			case 384:
				return jwtgo.SigningMethodES384.Sign(signingString, privateKeyType)
			case 521:
				return jwtgo.SigningMethodES512.Sign(signingString, privateKeyType)
			default:
				return "", fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case []byte:
		{
			switch macStrength {
			case MacStrength_256:
				return jwtgo.SigningMethodHS256.Sign(signingString, key)
			case MacStrength_384:
				return jwtgo.SigningMethodHS384.Sign(signingString, key)
			case MacStrength_512:
				return jwtgo.SigningMethodHS512.Sign(signingString, key)
			default:
				return "", fmt.Errorf("unsupported mac strength %T", macStrength)
			}
		}
	default:
		return "", fmt.Errorf("Unsupported key type %T", privateKeyType)
	}
}

func verifyMac(signingString string, signature string, key interface{}, macStrength MacStrength) error {
	switch publicKeyType := key.(type) {
	case *rsa.PrivateKey:
		{
			length := key.(*rsa.PrivateKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 384:
				return jwtgo.SigningMethodRS384.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 512:
				return jwtgo.SigningMethodRS512.Verify(signingString, signature, &publicKeyType.PublicKey)
			default:
				return fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case *ecdsa.PrivateKey:
		{
			length := key.(*ecdsa.PrivateKey).Curve.Params().BitSize

			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 384:
				return jwtgo.SigningMethodES384.Verify(signingString, signature, &publicKeyType.PublicKey)
			case 521:
				return jwtgo.SigningMethodES512.Verify(signingString, signature, &publicKeyType.PublicKey)
			default:
				return fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case *rsa.PublicKey:
		{
			length := key.(*rsa.PublicKey).N.BitLen() / 8
			switch length {
			case 256:
				return jwtgo.SigningMethodRS256.Verify(signingString, signature, publicKeyType)
			case 384:
				return jwtgo.SigningMethodRS384.Verify(signingString, signature, publicKeyType)
			case 512:
				return jwtgo.SigningMethodRS512.Verify(signingString, signature, publicKeyType)
			default:
				return fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case *ecdsa.PublicKey:
		{
			length := key.(*ecdsa.PublicKey).Curve.Params().BitSize

			switch length {
			case 256:
				return jwtgo.SigningMethodES256.Verify(signingString, signature, publicKeyType)
			case 384:
				return jwtgo.SigningMethodES384.Verify(signingString, signature, publicKeyType)
			case 521:
				return jwtgo.SigningMethodES512.Verify(signingString, signature, publicKeyType)
			default:
				return fmt.Errorf("unsupported signing method strength %T", length)
			}
		}
	case []byte:
		{
			switch macStrength {
			case MacStrength_256:
				return jwtgo.SigningMethodHS256.Verify(signingString, signature, key)
			case MacStrength_384:
				return jwtgo.SigningMethodHS384.Verify(signingString, signature, key)
			case MacStrength_512:
				return jwtgo.SigningMethodHS512.Verify(signingString, signature, key)
			default:
				return fmt.Errorf("unsupported mac strength %T", macStrength)
			}
		}
	default:
		return fmt.Errorf("Unsupported key type %T", publicKeyType)
	}
}
