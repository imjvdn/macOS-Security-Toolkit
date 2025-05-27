# macOS Security Toolkit Test Framework

This directory contains the test framework for the macOS Security Toolkit. The framework provides a way to validate that all scripts are functioning correctly and producing expected output.

## Overview

The test framework performs the following checks:
- Verifies that scripts exist and are executable
- Runs each script with test parameters to ensure they execute without errors
- Validates script output against expected patterns
- Generates a comprehensive test report

## Running Tests

To run the test suite:

```bash
# Navigate to the tests directory
cd tests

# Run the test script
./run-tests.sh
```

The test script will:
1. Run each script in the toolkit with safe test parameters
2. Collect output and verify it against expected patterns
3. Generate a test report in the `test_results_TIMESTAMP` directory

## Test Report

After running the tests, a report will be generated at `tests/test_results_TIMESTAMP/test_report.md`. This report includes:

- A summary of all tests run
- Pass/fail status for each script
- Notes about any failures
- Overall success rate

## Adding Tests for New Scripts

When adding new scripts to the toolkit, you should also add corresponding test cases to the `run-tests.sh` file:

1. Create a new test function following the pattern of existing test functions
2. Add appropriate checks for your script's expected behavior
3. Call your test function from the main execution section

Example test function template:

```bash
# Function to test your-new-script.sh
test_your_new_script() {
    local script_path="$SCRIPTS_DIR/path/to/your-new-script.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with safe parameters
    "$script_path" --safe-test-flag > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "expected" "$test_output" || grep -q "output" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}
```

## Best Practices for Testing

1. Always use `--dry-run` flags when available to prevent actual system changes
2. Direct output to test directories to avoid affecting the real system
3. Use pattern matching to verify script output rather than exact string matching
4. Test both normal operation and error handling
5. Run tests before merging new features into the develop branch
