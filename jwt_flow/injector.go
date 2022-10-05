package jwt_flow

import (
	"fmt"
	"net/http"
)

type TokenInjector func(req *http.Request, signedToken string) *http.Request

func AuthHeaderTokenInjector(req *http.Request, signedToken string) *http.Request {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", signedToken))
	return req
}

func CookieTokenInjector(cookieName string) TokenInjector {
	return func(req *http.Request, signedToken string) *http.Request {
		cookie := &http.Cookie{
			Name:  cookieName,
			Value: signedToken,
		}
		req.AddCookie(cookie)
		return req
	}
}

func ParameterTokenInjector(param string) TokenInjector {
	return func(req *http.Request, signedToken string) *http.Request {
		q := req.URL.Query()
		q.Add(param, signedToken)
		req.URL.RawQuery = q.Encode()
		return req
	}
}

func MultiTokenInjector(injectors ...TokenInjector) TokenInjector {
	return func(req *http.Request, signedToken string) *http.Request {
		for _, ex := range injectors {
			ex(req, signedToken)
		}
		return req
	}
}
