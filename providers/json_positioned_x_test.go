package providers

import (
	"strings"
	"testing"
)

// TestXProviderJSONPaths tests JSON path extraction for X (Twitter) provider
// Using actual X API response structure based on real API data
func TestXProviderJSONPaths(t *testing.T) {
	// Real X API response structure
	xAPIResponse := `{
  "data": {
    "user": {
      "result": {
        "rest_id": "2853538776",
        "core": {
          "created_at": "Sun Oct 12 22:06:29 +0000 2014",
          "screen_name": "LAITHALEBRAHIM"
        },
        "legacy": {
          "followers_count": 5,
          "friends_count": 71
        }
      }
    }
  }
}`

	tests := []struct {
		name         string
		jsonPath     string
		expectedText string
		description  string
	}{
		{
			name:         "followers_count",
			jsonPath:     "$.data.user.result.legacy.followers_count",
			expectedText: "5",
			description:  "Extract followers_count from legacy",
		},
		{
			name:         "friends_count",
			jsonPath:     "$.data.user.result.legacy.friends_count",
			expectedText: "71",
			description:  "Extract friends_count from legacy",
		},
		{
			name:         "created_at",
			jsonPath:     "$.data.user.result.core.created_at",
			expectedText: "+0000",
			description:  "Extract created_at from core",
		},
		{
			name:         "rest_id",
			jsonPath:     "$.data.user.result.rest_id",
			expectedText: "2853538776",
			description:  "Extract rest_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docBytes := []byte(xAPIResponse)

			// Call the extraction function
			ranges, err := ExtractJSONValueIndexes(docBytes, tt.jsonPath)

			if err != nil {
				t.Fatalf("ExtractJSONValueIndexes failed for %s: %v\nJSONPath: %s", tt.name, err, tt.jsonPath)
			}

			if len(ranges) == 0 {
				t.Fatalf("No ranges returned for %s\nJSONPath: %s", tt.name, tt.jsonPath)
			}

			// Extract the actual text from the first range
			firstRange := ranges[0]
			if firstRange.Start < 0 || firstRange.End > len(docBytes) {
				t.Fatalf("Invalid range for %s: start=%d, end=%d, docLen=%d", tt.name, firstRange.Start, firstRange.End, len(docBytes))
			}

			extracted := string(docBytes[firstRange.Start:firstRange.End])

			// Check if the extracted text contains the expected value
			if !strings.Contains(extracted, tt.expectedText) {
				t.Errorf("%s: Expected extraction to contain %q, but got %q\nJSONPath: %s\nRange: [%d:%d]",
					tt.name, tt.expectedText, extracted, tt.jsonPath, firstRange.Start, firstRange.End)
			}

			t.Logf("✅ %s: Successfully extracted: %q", tt.description, extracted)
		})
	}
}
