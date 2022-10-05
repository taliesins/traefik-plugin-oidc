package sso_redirector

import (
	"net/http"
	"net/url"
	"time"
)

func GetCookie(requestUrl *url.URL, value string) *http.Cookie {
	sessionCookie := http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		Domain:   requestUrl.Hostname(),
		Path:     "/",
	}

	return &sessionCookie
}

func GetExpiredSessionCookie(requestUrl *url.URL) *http.Cookie {
	sessionCookie := GetCookie(requestUrl, "")
	sessionCookie.MaxAge = -1
	sessionCookie.Expires = time.Now().Add(-100 * time.Hour)

	return sessionCookie
}
