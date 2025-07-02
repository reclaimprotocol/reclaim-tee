package shared

import (
	"encoding/json"
)

// JSONMarshal is a helper function to marshal JSON data
func JSONMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
