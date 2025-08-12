package providers

type TLSConnectionOptions struct {
	SupportedProtocolVersions []string `json:"supportedProtocolVersions,omitempty"`
}

type ResponseMatch struct {
	Value    string `json:"value,omitempty"`
	XPath    string `json:"xPath,omitempty"`
	JSONPath string `json:"jsonPath,omitempty"`
}

type ResponseRedaction struct {
	Regex    string `json:"regex,omitempty"`
	XPath    string `json:"xPath,omitempty"`
	JSONPath string `json:"jsonPath,omitempty"`
}

type HTTPProviderParams struct {
	URL                     string                `json:"url"`
	Method                  string                `json:"method"`
	GeoLocation             string                `json:"geoLocation,omitempty"`
	Headers                 map[string]string     `json:"headers,omitempty"`
	Body                    any                   `json:"body,omitempty"`
	WriteRedactionMode      string                `json:"writeRedactionMode,omitempty"`
	AdditionalClientOptions *TLSConnectionOptions `json:"additionalClientOptions,omitempty"`
	ParamValues             map[string]string     `json:"paramValues,omitempty"`
	ResponseMatches         []ResponseMatch       `json:"responseMatches,omitempty"`
	ResponseRedactions      []ResponseRedaction   `json:"responseRedactions,omitempty"`
}

type HTTPProviderSecretParams struct {
	CookieStr           string            `json:"cookieStr,omitempty"`
	AuthorisationHeader string            `json:"authorisationHeader,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	ParamValues         map[string]string `json:"paramValues,omitempty"`
}

type RedactedOrHashedArraySlice struct {
	From int     `json:"fromIndex"`
	To   int     `json:"toIndex"`
	Hash *string `json:"hash,omitempty"`
}

type CreateRequestResult struct {
	Data       []byte                       `json:"data"`
	Redactions []RedactedOrHashedArraySlice `json:"redactions"`
}
