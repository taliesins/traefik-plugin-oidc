package traefik_plugin_oidc

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"text/template"
	"time"

	guuid "github.com/google/uuid"
	"github.com/taliesins/traefik-plugin-oidc/jwks"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow/validator"
	"github.com/taliesins/traefik-plugin-oidc/log"
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
)

type Config struct {
	SsoRedirectUrlAddressTemplate     string                      `json:"SsoRedirectUrlAddressTemplate,omitempty"`
	SsoRedirectUrlMacClientSecret     string                      `json:"ssoRedirectUrlMacClientSecret,omitempty"`
	SsoRedirectUrlMacPrivateKey       string                      `json:"ssoRedirectUrlMacPrivateKey,omitempty"`
	SsoRedirectUrlMacStrength         sso_redirector.HmacStrength `json:"ssoRedirectUrlMacStrength,omitempty"`
	SsoRedirectUrlMacAllowedClockSkew time.Duration               `json:"ssoRedirectUrlMacAllowedClockSkew,omitempty"`

	ClientSecret         string `json:"clientSecret,omitempty"`
	PublicKey            string `json:"publicKey,omitempty"`
	Issuer               string `json:"issuer,omitempty"`
	Audience             string `json:"audience,omitempty"`
	JwksAddress          string `json:"jwksAddress,omitempty"`
	OidcDiscoveryAddress string `json:"oidcDiscoveryAddress,omitempty"`
	UseDynamicValidation bool   `json:"useDynamicValidation,omitempty"`

	AlgorithmValidationRegex string        `json:"algorithmValidationRegex,omitempty"`
	AudienceValidationRegex  string        `json:"audienceValidationRegex,omitempty"`
	IssuerValidationRegex    string        `json:"issuerValidationRegex,omitempty"`
	SubjectValidationRegex   string        `json:"subjectValidationRegex,omitempty"`
	IdValidationRegex        string        `json:"idValidationRegex,omitempty"`
	TokenAllowedClockSkew    time.Duration `json:"tokenAllowedClockSkew,omitempty"`
	IgnorePathRegex          string        `json:"ignorePathRegex,omitempty"`
	CredentialsOptional      bool          `json:"credentialsOptional,omitempty"`
	ValidateOnOptions        bool          `json:"validateOnOptions,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		SsoRedirectUrlAddressTemplate:     "",
		SsoRedirectUrlMacStrength:         sso_redirector.HmacStrength_256,
		SsoRedirectUrlMacClientSecret:     "",
		SsoRedirectUrlMacPrivateKey:       "",
		SsoRedirectUrlMacAllowedClockSkew: time.Minute * 30,

		ClientSecret:         "",
		PublicKey:            "",
		Issuer:               "",
		Audience:             "",
		JwksAddress:          "",
		OidcDiscoveryAddress: "",
		UseDynamicValidation: false,

		AlgorithmValidationRegex: "",
		AudienceValidationRegex:  "",
		IssuerValidationRegex:    "",
		SubjectValidationRegex:   "",
		IdValidationRegex:        "",
		TokenAllowedClockSkew:    time.Minute * 5,
		IgnorePathRegex:          "",
		CredentialsOptional:      false,
		ValidateOnOptions:        true,
	}
}

type Plugin struct {
	logger *log.Logger
	ctx    context.Context
	flow   jwt_flow.Flow
	config *Config
	name   string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var err error

	logger, err := log.NewLogger()
	if err != nil {
		err = fmt.Errorf("unable to intialize logger: %v", err)
		return nil, err
	}

	/*
		logger.Debug("Starting the traefik-plugin-oidc")
		logger.Sync()
	*/

	// Parse config
	// switch config.SsoRedirectUrlMacStrength {
	// case sso_redirector.HmacStrength_256: {}
	// case sso_redirector.HmacStrength_384: {}
	// case sso_redirector.HmacStrength_512: {}
	// default: {
	// 	config.SsoRedirectUrlMacStrength = sso_redirector.HmacStrength_256
	// }
	config.SsoRedirectUrlMacStrength = sso_redirector.HmacStrength_256

	if config.UseDynamicValidation == true && (config.Issuer == "" && config.IssuerValidationRegex == "") {
		logger.Warn("DANGER DANGER DANGER when 'UseDynamicValidation' = 'true' and 'Issuer' = '' and 'IssuerValidationRegex' = '', then tokens from any IdP will be trusted - this is an insecure configuration DANGER DANGER DANGER", nil)
	}

	if config.SsoRedirectUrlMacClientSecret == "" && config.SsoRedirectUrlMacPrivateKey == "" && config.SsoRedirectUrlAddressTemplate != "" {
		err = fmt.Errorf("config value 'SsoRedirectUrlMacPrivateKey' or 'SsoRedirectUrlMacClientSecret' must be set if config value 'SsoRedirectUrlAddressTemplate' is specified")
		logger.Fatal("Unable to parse config", []encoder.Field{encoder.Error(err)})
		return nil, err
	}

	if config.Issuer == "" && config.Audience == "" && config.JwksAddress == "" && config.OidcDiscoveryAddress == "" && config.UseDynamicValidation == false && config.ClientSecret == "" && config.SsoRedirectUrlMacPrivateKey == "" && config.SsoRedirectUrlMacClientSecret == "" && config.PublicKey == "" {
		err = fmt.Errorf("configuration must be set")
		logger.Fatal("Unable to parse config", []encoder.Field{encoder.Error(err)})
		return nil, err
	}

	if !(config.ClientSecret != "" || config.PublicKey != "" || config.OidcDiscoveryAddress != "" || config.JwksAddress != "" || (config.Issuer != "" && config.UseDynamicValidation == true)) && config.Audience != "" {
		err = fmt.Errorf("config value 'ClientSecret' or 'PublicKey' or 'OidcDiscoveryAddress' or 'JwksAddress' or 'Issuer' with UseDynamicValidation enabled, if config value 'Audience' is specified")
		logger.Fatal("Unable to parse config", []encoder.Field{encoder.Error(err)})
		return nil, err
	}

	if (config.ClientSecret == "" && config.PublicKey == "") && !(config.OidcDiscoveryAddress != "" || config.JwksAddress != "" || (config.Issuer != "" && config.UseDynamicValidation == true)) && config.SsoRedirectUrlAddressTemplate != "" {
		err = fmt.Errorf("'OidcDiscoveryAddress' or 'JwksAddress' or 'Issuer' with UseDynamicValidation enabled, if config value 'SsoRedirectUrlAddressTemplate' is specified and 'ClientSecret' and 'PublicKey' have not been configured")
		logger.Fatal("Unable to parse config", []encoder.Field{encoder.Error(err)})
		return nil, err
	}

	//Redirect url for SSO
	var ssoRedirectUrlAddressTemplate *template.Template

	if config.SsoRedirectUrlAddressTemplate != "" {
		ssoRedirectUrlAddressTemplate, err = sso_redirector.GetSsoRedirectUrlTemplate(config.SsoRedirectUrlAddressTemplate)
		if err != nil {
			logger.Fatal("Unable to parse config SsoRedirectUrlAddressTemplate", []encoder.Field{encoder.Error(err), encoder.String("SsoRedirectUrlAddressTemplate", config.SsoRedirectUrlAddressTemplate)})
			return nil, err
		}
	} else {
		ssoRedirectUrlAddressTemplate = nil
	}

	//Url hash using secret
	var urlHashClientSecret []byte
	if config.SsoRedirectUrlMacClientSecret != "" {
		urlHashClientSecret = []byte(config.SsoRedirectUrlMacClientSecret)
	} else {
		urlHashClientSecret = nil
	}

	//Url hash using private key
	var urlHashPrivateKey interface{}
	if config.SsoRedirectUrlMacPrivateKey != "" {
		urlHashPrivateKey, _, err = jwks.GetPrivateKeyFromFileOrContent(config.SsoRedirectUrlMacPrivateKey)
		if err != nil {
			logger.Fatal("Unable to parse config SsoRedirectUrlMacPrivateKey", []encoder.Field{encoder.Error(err)})
			return nil, err
		}
	} else {
		urlHashPrivateKey = nil
	}

	var ssoRedirectUrlMacSigningKey interface{}
	if urlHashPrivateKey != nil {
		ssoRedirectUrlMacSigningKey = urlHashPrivateKey
	} else if urlHashClientSecret != nil {
		ssoRedirectUrlMacSigningKey = urlHashClientSecret
	} else {
		ssoRedirectUrlMacSigningKey = nil
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
			logger.Fatal("Unable to parse config PublicKey", []encoder.Field{encoder.Error(err), encoder.String("PublicKey", config.PublicKey)})
			return nil, err
		}
	} else {
		publicKey = nil
	}

	//Validations
	var algorithmValidationRegex *regexp.Regexp
	if config.AlgorithmValidationRegex != "" {
		algorithmValidationRegex, err = regexp.Compile(config.AlgorithmValidationRegex)
		if err != nil {
			logger.Fatal("Unable to parse config AlgorithmValidationRegex", []encoder.Field{encoder.Error(err), encoder.String("AlgorithmValidationRegex", config.AlgorithmValidationRegex)})
			return nil, err
		}
	} else {
		algorithmValidationRegex = nil
	}

	var issuerValidationRegex *regexp.Regexp
	if config.IssuerValidationRegex != "" {
		issuerValidationRegex, err = regexp.Compile(config.IssuerValidationRegex)
		if err != nil {
			logger.Fatal("Unable to parse config IssuerValidationRegex", []encoder.Field{encoder.Error(err), encoder.String("IssuerValidationRegex", config.IssuerValidationRegex)})
			return nil, err
		}
	} else {
		issuerValidationRegex = nil
	}

	var audienceValidationRegex *regexp.Regexp
	if config.AudienceValidationRegex != "" {
		audienceValidationRegex, err = regexp.Compile(config.AudienceValidationRegex)
		if err != nil {
			logger.Fatal("Unable to parse config AudienceValidationRegex", []encoder.Field{encoder.Error(err), encoder.String("AudienceValidationRegex", config.AudienceValidationRegex)})
			return nil, err
		}
	} else {
		audienceValidationRegex = nil
	}

	var subjectValidationRegex *regexp.Regexp
	if config.SubjectValidationRegex != "" {
		subjectValidationRegex, err = regexp.Compile(config.SubjectValidationRegex)
		if err != nil {
			logger.Fatal("Unable to parse config SubjectValidationRegex", []encoder.Field{encoder.Error(err), encoder.String("SubjectValidationRegex", config.SubjectValidationRegex)})
			return nil, err
		}
	} else {
		subjectValidationRegex = nil
	}

	var idValidationRegex *regexp.Regexp
	if config.IdValidationRegex != "" {
		idValidationRegex, err = regexp.Compile(config.IdValidationRegex)
		if err != nil {
			logger.Fatal("Unable to parse config IdValidationRegex", []encoder.Field{encoder.Error(err), encoder.String("IdValidationRegex", config.IdValidationRegex)})
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
			logger.Fatal("Unable to parse config IgnorePathRegex", []encoder.Field{encoder.Error(err), encoder.String("IgnorePathRegex", config.IgnorePathRegex)})
			return nil, err
		}
	} else {
		ignorePathRegex = nil
	}

	errorHandler := jwt_flow.OidcErrorHandler(ssoRedirectUrlAddressTemplate, ssoRedirectUrlMacSigningKey, config.SsoRedirectUrlMacStrength)
	successHandler := jwt_flow.OidcSuccessHandler(ssoRedirectUrlMacSigningKey, config.SsoRedirectUrlMacStrength, config.SsoRedirectUrlMacAllowedClockSkew)
	tokenExtractor := jwt_flow.OidcTokenExtractor()
	tokenValidator := validator.OidcTokenValidator(
		algorithmValidationRegex,
		issuerValidationRegex,
		audienceValidationRegex,
		subjectValidationRegex,
		idValidationRegex,
		config.TokenAllowedClockSkew,
		clientSecret,
		publicKey,
		config.Issuer,
		config.JwksAddress,
		config.OidcDiscoveryAddress,
		config.UseDynamicValidation,
	)

	oidcMiddleware := jwt_flow.New(
		tokenValidator,
		jwt_flow.WithCredentialsOptional(config.CredentialsOptional),
		jwt_flow.WithValidateOnOptions(config.ValidateOnOptions),
		jwt_flow.WithIgnorePathOptions(ignorePathRegex),
		jwt_flow.WithTokenExtractor(tokenExtractor),
		jwt_flow.WithErrorHandler(errorHandler),
		jwt_flow.WithSuccessHandler(successHandler),
	)

	flow := oidcMiddleware.DefaultFlow(next)

	return &Plugin{
		logger: logger,
		ctx:    ctx,
		name:   name,
		config: config,
		flow:   flow,
	}, nil
}

const LogFieldRequestID = "requestID"

func (a *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	requestId := guuid.NewString()                                                                   //TODO: see if we can plugin to tracing plugins like jaeger/zipkin to get the tracing id. See  https://doc.traefik.io/traefik/observability/tracing/overview/
	loggerForRequest := a.logger.With([]encoder.Field{encoder.String(LogFieldRequestID, requestId)}) // it is a clone of the parent logger with the same properties but any additional changes will not be propagated to parent
	a.flow(loggerForRequest, rw, req)
	loggerForRequest.Sync()
}
