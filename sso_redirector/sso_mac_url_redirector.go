package sso_redirector

import (
	"fmt"
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

func AddMacHashToUrl(url *url.URL, macSigningKey interface{}, macStrength HmacStrength) error {
	hash, err := signHmac(url.String(), macSigningKey, macStrength)
	if err != nil {
		return err
	}
	q := url.Query()
	q.Set(HashQuerystringParameterName, hash)
	url.RawQuery = q.Encode()
	return nil
}

func VerifyAndStripMacHashFromUrl(url *url.URL, macSigningKey interface{}, macStrength HmacStrength) error {
	query := url.Query()

	signature := query.Get(HashQuerystringParameterName)
	if signature == "" {
		return fmt.Errorf("no %s querystring in uri", HashQuerystringParameterName)
	}

	q := url.Query()
	q.Del(HashQuerystringParameterName)
	url.RawQuery = q.Encode()

	return verifyHmac(url.String(), signature, macSigningKey, macStrength)
}

// var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
func GetRedirectorUrl(r *http.Request, macSigningKey interface{}, macStrength HmacStrength, nonce string, issuedAt string) (*url.URL, error) {
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

func GetRedirectUrl(r *http.Request, macSigningKey interface{}, macStrength HmacStrength, allowedClockSkew time.Duration) (*url.URL, error) {
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
