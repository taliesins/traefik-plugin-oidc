# Traefik Plugin OIDC

This plugin will allow ingress endpoints to be protected with SSO by using OIDC. Plugin will check for a valid token and redirect to SSO if one is not detected. Once a valid token is detected traffic will continue normally to the ingress. 

## Pre-requisites

* Golang
* Docker
* Make
  * For windows - https://gnuwin32.sourceforge.net/packages/make.htm & set PATH=%PATH%;C:\Program Files (x86)\GnuWin32\bin
* yaegi
  * From source code install - go install github.com/traefik/yaegi/cmd/yaegi@latest 

Recommend using a tool like [OpenLens](https://github.com/MuhammedKalkan/OpenLens/releases) to see whats happening inside the cluster.

## Setting up SSO

Configure SSO endpoint:
* client_id = `<value comes from sso>`
* response_type = `id_token`
* scope = at least `oidc` but might also be other scopes e.g. `oidc profile`

e.g. keycloak sso endpoint

general layout
```
http://keycloak.localhost/realms/<realm name>/protocol/openid-connect/auth?client_id=<client id>&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token
```

value that should be used in settings
```
http://keycloak.localhost/realms/whoami/protocol/openid-connect/auth?client_id=whoami-middleware-oidc-keycloak&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token
```


```
http://keycloak.localhost/realms/whoami/protocol/openid-connect/auth?client_id=whoami-middleware-oidc-keycloak&nonce=123123&redirect_uri=http://whoami.localhost/redirector&state=123123&scope=openid&response_type=id_token
```

