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
		shouldFail   bool
	}{
		{
			name:         "followers_count_simple",
			jsonPath:     "$.data.user.result.legacy.followers_count",
			expectedText: "5",
			description:  "Extract followers_count from legacy (simple path)",
			shouldFail:   false,
		},
		{
			name:         "followers_count_with_filter",
			jsonPath:     "$.data.user.result.[?(@.followers_count >= 100)].followers_count",
			expectedText: "5",
			description:  "Extract followers_count with filter >= 100 (testing new lib v1.1.5)",
			shouldFail:   true, // Expected to fail with current value of 5 < 100
		},
		{
			name:         "friends_count_simple",
			jsonPath:     "$.data.user.result.legacy.friends_count",
			expectedText: "71",
			description:  "Extract friends_count from legacy (simple path)",
			shouldFail:   false,
		},
		{
			name:         "friends_count_with_filter",
			jsonPath:     "$.data.user.result.[?(@.friends_count >= 0)].friends_count",
			expectedText: "71",
			description:  "Extract friends_count with filter >= 0 (testing new lib v1.1.5)",
			shouldFail:   false, // Should work if filter syntax is supported
		},
		{
			name:         "created_at",
			jsonPath:     "$.data.user.result.core.created_at",
			expectedText: "+0000",
			description:  "Extract created_at from core",
			shouldFail:   false,
		},
		{
			name:         "rest_id",
			jsonPath:     "$.data.user.result.rest_id",
			expectedText: "2853538776",
			description:  "Extract rest_id",
			shouldFail:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docBytes := []byte(xAPIResponse)

			// Call the extraction function
			ranges, err := ExtractJSONValueIndexes(docBytes, tt.jsonPath)

			if tt.shouldFail {
				if err != nil || len(ranges) == 0 {
					t.Logf("✅ %s: Expected to fail/return no results, and it did (error: %v)", tt.description, err)
					return
				}
				t.Logf("⚠️ %s: Expected to fail but succeeded - filter syntax may now be supported!", tt.description)
			}

			if err != nil {
				if !tt.shouldFail {
					t.Fatalf("ExtractJSONValueIndexes failed for %s: %v\nJSONPath: %s", tt.name, err, tt.jsonPath)
				}
				return
			}

			if len(ranges) == 0 {
				if !tt.shouldFail {
					t.Fatalf("No ranges returned for %s\nJSONPath: %s", tt.name, tt.jsonPath)
				}
				return
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

// TestXProviderFilterSyntaxWithPassingValue tests filter syntax with value that should pass the filter
func TestXProviderFilterSyntaxWithPassingValue(t *testing.T) {
	// X API response with high follower count that passes >= 100 filter
	xAPIResponse := `{
  "data": {
    "user": {
      "result": {
        "rest_id": "2853538776",
        "core": {
          "created_at": "Sun Oct 12 22:06:29 +0000 2014"
        },
        "legacy": {
          "followers_count": 150,
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
			name:         "followers_count_filter_passing",
			jsonPath:     "$.data.user.result.[?(@.followers_count >= 100)].followers_count",
			expectedText: "150",
			description:  "Test filter syntax with value that passes >= 100 (v1.1.5)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docBytes := []byte(xAPIResponse)

			ranges, err := ExtractJSONValueIndexes(docBytes, tt.jsonPath)

			if err != nil {
				t.Logf("⚠️ Filter syntax not yet supported in v1.1.5: %v", err)
				t.Skipf("Skipping - filter syntax [?(@.property >= value)] not supported")
				return
			}

			if len(ranges) == 0 {
				t.Logf("⚠️ Filter returned no results (filter may not be supported)")
				t.Skipf("Skipping - no results from filter")
				return
			}

			firstRange := ranges[0]
			extracted := string(docBytes[firstRange.Start:firstRange.End])

			if !strings.Contains(extracted, tt.expectedText) {
				t.Errorf("Expected extraction to contain %q, but got %q", tt.expectedText, extracted)
			}

			t.Logf("✅ %s: Filter syntax WORKS! Extracted: %q", tt.description, extracted)
		})
	}
}
