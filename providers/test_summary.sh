#!/bin/bash

# Run tests and capture output
echo "Running tests..."
output=$(go test -v -count=1 . 2>&1)

# Count results (escape special characters properly)
passed=$(echo "$output" | grep -c "\-\-\- PASS:")
failed=$(echo "$output" | grep -c "\-\-\- FAIL:")
skipped=$(echo "$output" | grep -c "\-\-\- SKIP:")
total=$((passed + failed + skipped))

# Print summary
echo "================================"
echo "TEST SUMMARY"
echo "================================"
echo "PASSED:  $passed"
echo "FAILED:  $failed" 
echo "SKIPPED: $skipped"
echo "TOTAL:   $total"
echo "================================"

# Show failed tests if any
if [ $failed -gt 0 ]; then
    echo "FAILED TESTS:"
    echo "$output" | grep "\-\-\- FAIL:" | sed 's/\-\-\- FAIL: /  - /'
    echo "================================"
fi

# Show skipped tests if any
if [ $skipped -gt 0 ]; then
    echo "SKIPPED TESTS:"
    echo "$output" | grep "\-\-\- SKIP:" | sed 's/\-\-\- SKIP: /  - /'
    echo "================================"
fi

# Exit with appropriate code
if [ $failed -gt 0 ]; then
    exit 1
else
    exit 0
fi
