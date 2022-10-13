package sso_redirector

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
	htmlTemplate "text/template"
)

var SessionCookieName = "id_token"

type ssoRedirectUrlTemplateOptions struct {
	CallbackUrl string
	State       string
	Nonce       string
	IssuedAt    string
}

// "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=12345678-1234-1234-1234-1234567890ab&nonce={{.Nonce}}&redirect_uri={{.Url}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
func GetSsoRedirectUrlTemplate(templateToRender string) (*template.Template, error) {
	return template.New("SsoRedirectUrl").Parse(templateToRender)
}

// var redirectUrlTemplate = `https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=12345678-1234-1234-1234-1234567890ab&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login`
func RenderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate *template.Template, urlToRedirectTo *url.URL, nonce string, issuedAt string) (*url.URL, error) {
	//We want to only use a hard coded host and path in the callback page. The hash ensures that the correct full path is required when doing a redirect. This also reduces the size of the state querystring parameter
	state := urlToRedirectTo.Query().Encode()
	callbackUrl, err := url.Parse(urlToRedirectTo.String())
	if err != nil {
		return nil, err
	}

	callbackUrl.RawQuery = ""
	callbackUrl.Path = CallbackPath

	var redirectSsoUrlTemplateRendered bytes.Buffer
	err = ssoRedirectUrlTemplate.Execute(&redirectSsoUrlTemplateRendered, ssoRedirectUrlTemplateOptions{
		CallbackUrl: url.QueryEscape(callbackUrl.String()),
		State:       url.QueryEscape(state),
		Nonce:       url.QueryEscape(nonce),
		IssuedAt:    url.QueryEscape(issuedAt),
	})

	if err != nil {
		return nil, err
	}

	ssoRedirectUrl, err := url.Parse(redirectSsoUrlTemplateRendered.String())
	if err != nil {
		return nil, err
	}

	return ssoRedirectUrl, nil
}

type redirectToSsoPageTemplateOptions struct {
	RedirectUrl  *url.URL
	ErrorMessage string
}

var attributeReplacer = strings.NewReplacer(
	"\u0000", "\uFFFD",
	"\"", "&#34;",
	"'", "&#39;",
	"+", "&#43;",
	"<", "&lt;",
	">", "&gt;",
)

var redirectToSsoPageTemplate = template.Must(template.New("RedirectToSsoPage").Funcs(template.FuncMap{
	"escapeJavascriptVariable": func(textToEscape *url.URL) string {
		return htmlTemplate.JSEscapeString(textToEscape.String())
	},
	"escapeHtml": func(textToEscape *url.URL) string {
		return htmlTemplate.HTMLEscapeString(textToEscape.String())
	},
	"escapeAttribute": func(textToEscape *url.URL) string {
		return attributeReplacer.Replace(textToEscape.String())
	},
}).Parse(`
<!DOCTYPE html><html><head><title></title></head><body>
{{.ErrorMessage}}
<script>
window.location.replace('{{ .RedirectUrl | escapeJavascriptVariable }}');
</script>
Please sign in at <a href='{{.RedirectUrl | escapeAttribute}}'>{{ .RedirectUrl | escapeHtml}}</a>
</body></html>
`))

func RenderRedirectToSsoPageTemplate(redirectUrl *url.URL, errorMessage string) (string, error) {
	var redirectToSingleSignOnTemplateRendered bytes.Buffer
	err := redirectToSsoPageTemplate.Execute(&redirectToSingleSignOnTemplateRendered, redirectToSsoPageTemplateOptions{
		RedirectUrl:  redirectUrl,
		ErrorMessage: errorMessage,
	})

	if err != nil {
		return "", err
	}

	return redirectToSingleSignOnTemplateRendered.String(), nil
}

type ssoCallbackPageTemplateOptions struct {
	RedirectorUrl                string
	UseCookieRedirect            bool
	SessionCookieName            string
	IdTokenBookmarkParameterName string
	StateBookmarkParameterName   string
}

var ssoCallbackPageTemplate = template.Must(template.New("SsoCallbackPage").Funcs(template.FuncMap{
	"escapeJavascriptVariable": func(textToEscape string) string {
		return htmlTemplate.JSEscapeString(textToEscape)
	},
}).Parse(`
<!DOCTYPE html><html><head><title></title></head><body>
<script>
function getBookMarkParameterByName(name, url) {
    if (!url) url = window.location.hash;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[#&?]" + name + "(=([^&#]*)|&|#|$)"), results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}
{{ if not .UseCookieRedirect }}
function post(path, params, method) {
    method = method || "post"; // Set method to post by default if not specified.
    // The rest of this code assumes you are not using a library.
    // It can be made less wordy if you use one.
    var form = document.createElement("form");
    form.setAttribute("method", method);
    form.setAttribute("action", path);
    for(var key in params) {
        if(params.hasOwnProperty(key)) {
            var hiddenField = document.createElement("input");
            hiddenField.setAttribute("type", "hidden");
            hiddenField.setAttribute("name", key);
            hiddenField.setAttribute("value", params[key]);
            form.appendChild(hiddenField);
        }
    }
    document.body.appendChild(form);
    form.submit();
}
{{ end }}
state = getBookMarkParameterByName('{{ escapeJavascriptVariable .StateBookmarkParameterName}}');
if (state) {
	id_token = getBookMarkParameterByName('{{ escapeJavascriptVariable .IdTokenBookmarkParameterName}}');
	if (id_token) {
{{ if not .UseCookieRedirect }}
		post('{{ escapeJavascriptVariable .RedirectorUrl}}?' + state, {id_token: id_token});
{{ else }}
		document.cookie = '{{ escapeJavascriptVariable .SessionCookieName}}=' + id_token + '; domain=' + document.domain + '; path=/; secure';
		window.location.replace('{{ escapeJavascriptVariable .RedirectorUrl}}?' + state);
{{ end }}
	}
}
</script>
Please change the '#' in the url to '&' and goto link
</body></html>
`))

func RenderSsoCallbackPageTemplate(redirectorUrl *url.URL) (string, error) {
	redirectorUrlWithoutQuerystring, err := url.Parse(redirectorUrl.String())
	if err != nil {
		return "", err
	}

	//Strip querystring as this is coming from the state parameter
	redirectorUrlWithoutQuerystring.RawQuery = ""

	var idTokenInBookmarkRedirectPageTemplateRendered bytes.Buffer
	err = ssoCallbackPageTemplate.Execute(&idTokenInBookmarkRedirectPageTemplateRendered, ssoCallbackPageTemplateOptions{
		RedirectorUrl:                redirectorUrlWithoutQuerystring.String(),
		UseCookieRedirect:            false,
		SessionCookieName:            SessionCookieName,
		IdTokenBookmarkParameterName: IdTokenBookmarkParameterName,
		StateBookmarkParameterName:   StateBookmarkParameterName,
	})

	if err != nil {
		return "", err
	}

	return idTokenInBookmarkRedirectPageTemplateRendered.String(), nil
}

func TemplateToRegexFixer(template string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		//".", "\\.", // will break {{.Url}}
		//"{", "\\{", // will break {{.Url}}
		"/", `\/`,
		"^", `\^`,
		"$", `\$`,
		"*", `\*`,
		"+", `\+`,
		"?", `\?`,
		"(", `\(`,
		")", `\)`,
		"[", `\[`,
		"|", `\|`,
	)

	return replacer.Replace(template)
}

func JSUnescapeString(template string) string {
	replacer := strings.NewReplacer(
		`\u003D`, `=`,
		`\u0026`, `&`,
		`\u003E`, `>`,
		`\u003C`, `<`,
		`\"`, `"`,
		`\'`, "'",
		`\\`, `\`,
	)

	return replacer.Replace(template)
}
