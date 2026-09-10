package providers

import "testing"

func TestGetHostPortPortBounds(t *testing.T) {
	for _, tt := range []struct {
		name    string
		port    string
		want    int
		wantErr bool
	}{
		{name: "minimum", port: "1", want: 1},
		{name: "HTTPS default", port: "443", want: 443},
		{name: "custom", port: "8443", want: 8443},
		{name: "maximum", port: "65535", want: 65535},
		{name: "leading zeros", port: "00443", want: 443},
		{name: "zero", port: "0", wantErr: true},
		{name: "negative", port: "-1", wantErr: true},
		{name: "above TCP maximum", port: "65536", wantErr: true},
		{name: "int32 maximum", port: "2147483647", wantErr: true},
		{name: "int32 overflow", port: "2147483648", wantErr: true},
		{name: "wraps to HTTPS default", port: "4294967739", wantErr: true},
		{name: "uint64 overflow", port: "18446744073709551616", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, authority := range []string{"example.com", "[2001:db8::1]"} {
				t.Run(authority, func(t *testing.T) {
					params := &HTTPProviderParams{URL: "https://" + authority + ":" + tt.port + "/path"}
					_, got, err := GetHostPort(params, &HTTPProviderSecretParams{})
					if tt.wantErr {
						if err == nil {
							t.Fatalf("GetHostPort accepted invalid port %q as %d", tt.port, got)
						}
						return
					}
					if err != nil || got != tt.want {
						t.Fatalf("GetHostPort port = %d, error = %v; want %d, nil", got, err, tt.want)
					}
				})
			}
		})
	}
}
