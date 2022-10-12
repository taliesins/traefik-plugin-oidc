package pluginoidc

import (
	"context"
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/jwks"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow/validator"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"github.com/traefik/traefik/v2/pkg/log"
	"net/http"
	"regexp"
	"text/template"
	"time"
)

type Config struct {
	ClientSecret         string `json:"clientSecret,omitempty"`
	PublicKey            string `json:"publicKey,omitempty"`
	Issuer               string `json:"issuer,omitempty"`
	Audience             string `json:"audience,omitempty"`
	JwksAddress          string `json:"jwksAddress,omitempty"`
	OidcDiscoveryAddress string `json:"oidcDiscoveryAddress,omitempty"`
	UseDynamicValidation bool   `json:"useDynamicValidation,omitempty"`
	SsoAddressTemplate   string `json:"ssoAddressTemplate,omitempty"`
	UrlMacClientSecret   string `json:"urlMacClientSecret,omitempty"`
	UrlMacPrivateKey     string `json:"urlMacPrivateKey,omitempty"`

	AlgorithmValidationRegex string        `json:"algorithmValidationRegex,omitempty"`
	AudienceValidationRegex  string        `json:"audienceValidationRegex,omitempty"`
	IssuerValidationRegex    string        `json:"issuerValidationRegex,omitempty"`
	SubjectValidationRegex   string        `json:"subjectValidationRegex,omitempty"`
	IdValidationRegex        string        `json:"idValidationRegex,omitempty"`
	AllowedClockSkew         time.Duration `json:"allowedClockSkew,omitempty"`
	IgnorePathRegex          string        `json:"ignorePathRegex,omitempty"`
	CredentialsOptional      bool          `json:"credentialsOptional,omitempty"`
	ValidateOnOptions        bool          `json:"validateOnOptions,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ClientSecret:         "",
		PublicKey:            "",
		Issuer:               "",
		Audience:             "",
		JwksAddress:          "",
		OidcDiscoveryAddress: "",
		UseDynamicValidation: false,
		SsoAddressTemplate:   "",
		UrlMacClientSecret:   "",
		UrlMacPrivateKey:     "",

		AlgorithmValidationRegex: "",
		AudienceValidationRegex:  "",
		IssuerValidationRegex:    "",
		SubjectValidationRegex:   "",
		IdValidationRegex:        "",
		AllowedClockSkew:         time.Minute * 5,
		IgnorePathRegex:          "",
		CredentialsOptional:      false,
		ValidateOnOptions:        true,
	}
}

type Plugin struct {
	ctx    context.Context
	next   http.Handler
	config *Config
	name   string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if config.Issuer == "" && config.Audience == "" && config.JwksAddress == "" && config.OidcDiscoveryAddress == "" && config.UseDynamicValidation == false && config.ClientSecret == "" && config.UrlMacPrivateKey == "" && config.UrlMacClientSecret == "" && config.PublicKey == "" {
		return nil, fmt.Errorf("configuration must be set")
	}

	if config.ClientSecret == "" && config.PublicKey == "" && config.Issuer == "" && config.OidcDiscoveryAddress == "" && config.JwksAddress == "" && config.Audience != "" && config.UseDynamicValidation {
		return nil, fmt.Errorf("config value 'ClientSecret' or 'PublicKey' or 'Issuer' or 'OidcDiscoveryAddress' or 'JwksAddress' must be set if config value 'Audience' is specified")
	}

	if config.Issuer == "" && config.OidcDiscoveryAddress == "" && config.JwksAddress == "" && config.UseDynamicValidation && config.SsoAddressTemplate != "" {
		return nil, fmt.Errorf("config value 'Issuer' or 'OidcDiscoveryAddress' or 'JwksAddress' must be set if config value 'SsoAddressTemplate' is specified")
	}

	if config.UrlMacClientSecret == "" && config.UrlMacPrivateKey == "" && config.SsoAddressTemplate != "" {
		return nil, fmt.Errorf("config value 'UrlMacPrivateKey' or 'UrlMacClientSecret' must be set if config value 'SsoAddressTemplate' is specified")
	}

	var err error

	//Redirect url for SSO
	var ssoRedirectUrlTemplate *template.Template
	if config.SsoAddressTemplate != "" {
		ssoRedirectUrlTemplate, err = sso_redirector.GetSsoRedirectUrlTemplate(config.SsoAddressTemplate)
		if err != nil {
			log.Errorf("Unable to parse config SsoAddressTemplate: %s", err)
			return nil, err
		}
	} else {
		ssoRedirectUrlTemplate = nil
	}

	//Standard client secret Jwt validation
	var clientSecret []byte
	if config.ClientSecret != "" {
		clientSecret = []byte(config.ClientSecret)
	} else {
		clientSecret = nil
	}

	//Standard certificate Jwt validation
	var publicKey interface{}
	if config.PublicKey != "" {
		publicKey, _, err = jwks.GetPublicKeyFromFileOrContent(config.PublicKey)
		if err != nil {
			log.Errorf("Unable to parse config PublicKey: %s", err)
			return nil, err
		}
	} else {
		publicKey = nil
	}

	//Url hash using secret
	var urlHashClientSecret []byte
	if config.UrlMacClientSecret != "" {
		urlHashClientSecret = []byte(config.UrlMacClientSecret)
	} else {
		urlHashClientSecret = nil
	}

	//Url hash using private key
	var urlHashPrivateKey interface{}
	if config.UrlMacPrivateKey != "" {
		urlHashPrivateKey, _, err = jwks.GetPrivateKeyFromFileOrContent(config.UrlMacPrivateKey)
		if err != nil {
			log.WithoutContext().Errorf("Unable to parse config UrlMacPrivateKey: %s", err)
			return nil, err
		}
	} else {
		urlHashPrivateKey = nil
	}

	//Validations
	var algorithmValidationRegex *regexp.Regexp
	if config.AlgorithmValidationRegex != "" {
		algorithmValidationRegex, err = regexp.Compile(config.AlgorithmValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AlgorithmValidationRegex: %s", err)
			return nil, err
		}
	} else {
		algorithmValidationRegex = nil
	}

	var issuerValidationRegex *regexp.Regexp
	if config.IssuerValidationRegex != "" {
		issuerValidationRegex, err = regexp.Compile(config.IssuerValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config IssuerValidationRegex: %s", err)
			return nil, err
		}
	} else {
		issuerValidationRegex = nil
	}

	var audienceValidationRegex *regexp.Regexp
	if config.AudienceValidationRegex != "" {
		audienceValidationRegex, err = regexp.Compile(config.AudienceValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AudienceValidationRegex: %s", err)
			return nil, err
		}
	} else {
		audienceValidationRegex = nil
	}

	var subjectValidationRegex *regexp.Regexp
	if config.SubjectValidationRegex != "" {
		subjectValidationRegex, err = regexp.Compile(config.SubjectValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AudienceValidationRegex: %s", err)
			return nil, err
		}
	} else {
		subjectValidationRegex = nil
	}

	var idValidationRegex *regexp.Regexp
	if config.IdValidationRegex != "" {
		idValidationRegex, err = regexp.Compile(config.IdValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config IdValidationRegex: %s", err)
			return nil, err
		}
	} else {
		idValidationRegex = nil
	}

	//Paths to skip OIDC on
	var ignorePathRegex *regexp.Regexp
	if config.IgnorePathRegex != "" {
		ignorePathRegex, err = regexp.Compile(config.IgnorePathRegex)
		if err != nil {
			log.Errorf("Unable to parse config IgnorePathRegex: %s", err)
			return nil, err
		}
	} else {
		ignorePathRegex = nil
	}

	var key interface{}
	if urlHashPrivateKey != nil {
		key = urlHashPrivateKey
	} else if urlHashClientSecret != nil {
		key = urlHashClientSecret
	} else {
		key = nil
	}

	macStrength := sso_redirector.MacStrength_256

	errorHandler := jwt_flow.OidcErrorHandler(ssoRedirectUrlTemplate, key, macStrength)
	tokenExtractor := jwt_flow.OidcTokenExtractor()
	tokenValidator := validator.OidcTokenValidator(
		algorithmValidationRegex,
		issuerValidationRegex,
		audienceValidationRegex,
		subjectValidationRegex,
		idValidationRegex,
		config.AllowedClockSkew,
		clientSecret,
		publicKey,
		config.Issuer,
		config.JwksAddress,
		config.OidcDiscoveryAddress,
		config.UseDynamicValidation,
	)

	oidcMiddleware := jwt_flow.New(tokenValidator,
		jwt_flow.WithCredentialsOptional(config.CredentialsOptional),
		jwt_flow.WithValidateOnOptions(config.ValidateOnOptions),
		jwt_flow.WithIgnorePathOptions(ignorePathRegex),
		jwt_flow.WithTokenExtractor(tokenExtractor),
		jwt_flow.WithErrorHandler(errorHandler),
	)

	oidcHandler := oidcMiddleware.CheckJWT(next)

	return &Plugin{
		ctx:    ctx,
		name:   name,
		config: config,
		next:   oidcHandler,
	}, nil
}

func (a *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.next.ServeHTTP(rw, req)
}
