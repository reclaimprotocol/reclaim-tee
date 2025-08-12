package providers

import (
	"strings"
	"testing"
)

func TestCreateRequest_AuthRequired(t *testing.T) {
	params := HTTPProviderParams{URL: "https://example.com", Method: "GET"}
	secret := HTTPProviderSecretParams{}
	if _, err := CreateRequest(secret, params); err == nil {
		t.Fatalf("expected error for missing auth, got nil")
	}
}

func TestCreateRequest_ReplacesParamsInBodyCorrectly(t *testing.T) {
	params := HTTPProviderParams{
		URL:    "https://example.{{param1}}/",
		Method: "GET",
		Body:   "hello {{h}} {{b}} {{h1h1h1h1h1h1h1}} {{h2}} {{a}} {{h1h1h1h1h1h1h1}} {{h}} {{a}} {{h2}} {{a}} {{b}} world",
		ParamValues: map[string]string{
			"param1": "com",
			"param2": "Example",
			"param3": "title",
			"what":   "illustrative",
			"a":      "{{b}}",
			"b":      "aaaaa",
		},
		Headers: map[string]string{"user-agent": "Mozilla/5.0"},
	}
	secret := HTTPProviderSecretParams{
		CookieStr:           "<cookie-str>",
		AuthorisationHeader: "abc",
		ParamValues: map[string]string{
			"h":              "crazy",
			"h1h1h1h1h1h1h1": "crazy1",
			"h2":             "crazy2",
		},
	}
	res, err := CreateRequest(secret, params)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	reqText := string(res.Data)
	if want := "hello crazy aaaaa crazy1 crazy2 {{b}} crazy1 crazy {{b}} crazy2 {{b}} aaaaa world"; !contains(reqText, want) {
		t.Fatalf("request body missing expected content: %q", want)
	}
	if len(res.Redactions) != 7 {
		t.Fatalf("expected 7 redactions, got %d", len(res.Redactions))
	}
	if got := getRedactionString(res, 0); got != "Cookie: <cookie-str>\r\nAuthorization: abc" {
		t.Fatalf("redaction[0] mismatch: %q", got)
	}
	if getRedactionString(res, 1) != "crazy" {
		t.Fatalf("redaction[1] mismatch")
	}
	if getRedactionString(res, 2) != "crazy1" {
		t.Fatalf("redaction[2] mismatch")
	}
	if getRedactionString(res, 3) != "crazy2" {
		t.Fatalf("redaction[3] mismatch")
	}
	if getRedactionString(res, 4) != "crazy1" {
		t.Fatalf("redaction[4] mismatch")
	}
	if getRedactionString(res, 5) != "crazy" {
		t.Fatalf("redaction[5] mismatch")
	}
	if getRedactionString(res, 6) != "crazy2" {
		t.Fatalf("redaction[6] mismatch")
	}
}

func TestCreateRequest_ReplacesParamsInBodyCase2(t *testing.T) {
	params := HTTPProviderParams{
		URL:    "https://www.kaggle.com",
		Method: "POST",
		Body:   "{\"includeGroups\":{{REQ_DAT}},\"includeLogins\":{{REQ_SECRET}},\"includeVerificationStatus\":false}",
		ParamValues: map[string]string{
			"REQ_DAT":  "false",
			"username": "testyreclaim",
		},
	}
	secret := HTTPProviderSecretParams{
		AuthorisationHeader: "abc",
		ParamValues:         map[string]string{"REQ_SECRET": "false"},
	}
	res, err := CreateRequest(secret, params)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	reqText := string(res.Data)
	if want := "{\"includeGroups\":false,\"includeLogins\":false,\"includeVerificationStatus\":false}"; !contains(reqText, want) {
		t.Fatalf("request body missing expected content: %q", want)
	}
	if len(res.Redactions) != 2 {
		t.Fatalf("expected 2 redactions, got %d", len(res.Redactions))
	}
	if getRedactionString(res, 0) != "Authorization: abc" {
		t.Fatalf("redaction[0] mismatch")
	}
	if getRedactionString(res, 1) != "false" {
		t.Fatalf("redaction[1] mismatch")
	}
}

func TestCreateRequest_ReplacesSecretParamsInURL(t *testing.T) {
	params := HTTPProviderParams{
		URL:    "https://www.kaggle.com/{{auth_token}}?request={{param_request}}",
		Method: "POST",
	}
	secret := HTTPProviderSecretParams{
		AuthorisationHeader: "abc",
		ParamValues: map[string]string{
			"auth_token":    "1234567890",
			"param_request": "select * from users",
		},
	}
	res, err := CreateRequest(secret, params)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	reqText := string(res.Data)
	if !contains(reqText, "POST /1234567890?request=select * from users HTTP/1.1") {
		t.Fatalf("request line not replaced as expected: %s", reqText)
	}
	if len(res.Redactions) != 3 {
		t.Fatalf("expected 3 redactions, got %d", len(res.Redactions))
	}
	if getRedactionString(res, 2) != "Authorization: abc" {
		t.Fatalf("redaction[2] mismatch")
	}
	if getRedactionString(res, 0) != "1234567890" {
		t.Fatalf("redaction[0] mismatch")
	}
	if getRedactionString(res, 1) != "select * from users" {
		t.Fatalf("redaction[1] mismatch")
	}
}

func TestCreateRequest_ShouldPanicOnNonPresentSecretParam(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for missing secret param")
		} else {
			msg := toString(r)
			if !strings.Contains(msg, "parameter's \"com\" value not found in paramValues and secret parameter's paramValues") {
				t.Fatalf("unexpected panic message: %s", msg)
			}
		}
	}()
	secret := HTTPProviderSecretParams{CookieStr: "abc"}
	params := HTTPProviderParams{URL: "https://xargs.{{com}}", Method: "GET"}
	_, _ = CreateRequest(secret, params)
}

// helpers
func getRedactionString(res CreateRequestResult, index int) string {
	return string(res.Data[res.Redactions[index].From:res.Redactions[index].To])
}

func contains(s, substr string) bool { return strings.Contains(s, substr) }

func toString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return ""
	}
}
