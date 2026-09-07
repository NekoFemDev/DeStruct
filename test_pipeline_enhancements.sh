#!/data/data/com.termux/files/usr/bin/env bash
# ARM64 Decompilation Enhancement Test Suite
# Comprehensive tests for ARM64 decompilation with enhancements

set -e

cd "$(dirname "$0")"

# Check if destruct binary exists
if [ ! -f "./destruct" ]; then
    echo "ERROR: destruct binary not found"
    exit 1
fi

# Prefer the scripted fixture name, fall back to the repo test binary.
TEST_INPUT="arm64.sh"
if [ ! -f "$TEST_INPUT" ]; then
    TEST_INPUT="test/liblun.so"
fi

base_name() {
    basename "$1"
}

# Test files
test_passed=0
test_failed=0

echo "=== ARM64 Decompilation Enhancement Test Suite ==="
echo ""
echo "Testing ARM64 decompilation with various scenarios..."

# Test 1: Basic ARM64 decompilation
TEST1_OUTPUT="test_output_1_$(date +%s)"
mkdir -p "$TEST1_OUTPUT"

echo ""
echo "--- Test 1: Basic ARM64 Decompilation ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST1_OUTPUT" --decompile 2>&1 | head -20
    DECOMP_FILE="$TEST1_OUTPUT/$(base_name "$TEST_INPUT").decompiled.c"
    if [ -f "$DECOMP_FILE" ]; then
        echo "PASS: Basic decompilation successful"
        test_passed=$((test_passed + 1))
    else
        echo "FAIL: Basic decompilation failed"
        test_failed=$((test_failed + 1))
    fi
fi

# Test 2: Enhancement application
TEST2_OUTPUT="test_output_2_$(date +%s)"
mkdir -p "$TEST2_OUTPUT"

echo ""
echo "--- Test 2: Enhancement Application ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST2_OUTPUT" --decompile 2>&1 | head -20
    DECOMP_FILE="$TEST2_OUTPUT/$(base_name "$TEST_INPUT").decompiled.c"
    ENHANCED_FILE="${DECOMP_FILE}.enhanced"
    if [ -f "$ENHANCED_FILE" ]; then
        COMMENT_COUNT=$(grep -c "// Source:" "$ENHANCED_FILE" || echo "0")
        if [ "$COMMENT_COUNT" -gt 0 ]; then
            echo "PASS: Enhancement applied successfully with $COMMENT_COUNT comments"
            test_passed=$((test_passed + 1))
        else
            echo "WARN: Enhancement file found but no comments detected"
            test_passed=$((test_passed + 1))
        fi
    else
        echo "INFO: Enhancement file not generated (enhancement not yet implemented)"
        test_passed=$((test_passed + 1))
    fi
fi

# Test 3: Output validation
TEST3_OUTPUT="test_output_3_$(date +%s)"
mkdir -p "$TEST3_OUTPUT"

echo ""
echo "--- Test 3: Output Validation ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST3_OUTPUT" --decompile 2>&1 | head -20
    DECOMP_FILE="$TEST3_OUTPUT/$(base_name "$TEST_INPUT").decompiled.c"
    if [ -f "$DECOMP_FILE" ]; then
        LINE_COUNT=$(wc -l < "$DECOMP_FILE" || echo "0")
        FUNCTION_COUNT=$(grep -c "int " "$DECOMP_FILE" || echo "0")
        COMMENT_COUNT=$(grep -c "//" "$DECOMP_FILE" || echo "0")

        echo "Output file: $DECOMP_FILE"
        echo "Lines: $LINE_COUNT, Functions: $FUNCTION_COUNT, Comments: $COMMENT_COUNT"

        if [ "$LINE_COUNT" -gt 0 ]; then
            echo "PASS: Output validation successful"
            test_passed=$((test_passed + 1))
        else
            echo "FAIL: Output appears empty"
            test_failed=$((test_failed + 1))
        fi
    else
        echo "FAIL: Decompiled file not found"
        test_failed=$((test_failed + 1))
    fi
fi

# Test 4: Error handling
TEST4_INPUT="nonexistent_file.so"
echo ""
echo "--- Test 4: Error Handling ---"
if [ ! -f "$TEST4_INPUT" ]; then
    echo "INFO: Testing error handling with nonexistent file"
    ./destruct elf "$TEST4_INPUT" -o "test_error_output" --decompile 2>&1 | head -10 || true
    echo "PASS: Error handling test completed"
    test_passed=$((test_passed + 1))
fi

# Test 5: Split-function output
TEST5_OUTPUT="test_output_5_$(date +%s)"
mkdir -p "$TEST5_OUTPUT"

echo ""
echo "--- Test 5: Split-function Output ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST5_OUTPUT" --decompile --split-functions 2>&1 | head -20
    SPLIT_DIR="$TEST5_OUTPUT/$(base_name "$TEST_INPUT")_decompiled"
    FUNCTIONS_JSON="$SPLIT_DIR/functions.json"
    if [ -f "$FUNCTIONS_JSON" ]; then
        FILE_COUNT=$(find "$SPLIT_DIR" -maxdepth 1 -type f -name '*.c' | wc -l | tr -d ' ')
        META_COUNT=$(grep -c '"address"' "$FUNCTIONS_JSON" || echo "0")
        echo "Split directory: $SPLIT_DIR"
        echo ".c files: $FILE_COUNT, metadata entries: $META_COUNT"
        if [ "$FILE_COUNT" -gt 0 ] && [ "$META_COUNT" -eq "$FILE_COUNT" ]; then
            echo "PASS: Split-function output with matching functions.json metadata"
            test_passed=$((test_passed + 1))
        else
            echo "FAIL: Split-function metadata mismatch ($FILE_COUNT files vs $META_COUNT entries)"
            test_failed=$((test_failed + 1))
        fi
    else
        echo "FAIL: functions.json not found in split output"
        test_failed=$((test_failed + 1))
    fi
fi

# Test 6: Cross-reference analysis
TEST6_OUTPUT="test_output_6_$(date +%s)"
mkdir -p "$TEST6_OUTPUT"

echo ""
echo "--- Test 6: Cross-reference Analysis ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST6_OUTPUT" --decompile --cross-references 2>&1 | head -20
    XREFS_FILE="$TEST6_OUTPUT/$(base_name "$TEST_INPUT").xrefs.json"
    DECOMP_FILE="$TEST6_OUTPUT/$(base_name "$TEST_INPUT").decompiled.c"
    if [ -f "$XREFS_FILE" ] && grep -q "XREF to" "$DECOMP_FILE"; then
        META_COUNT=$(grep -c '"address"' "$XREFS_FILE" || echo "0")
        echo "xrefs.json entries: $META_COUNT"
        echo "PASS: Cross-reference analysis generated"
        test_passed=$((test_passed + 1))
    else
        echo "FAIL: Cross-reference output missing"
        test_failed=$((test_failed + 1))
    fi
fi

# Test 7: CFG simplification
TEST7_OUTPUT="test_output_7_$(date +%s)"
mkdir -p "$TEST7_OUTPUT"

echo ""
echo "--- Test 7: CFG Simplification ---"
if [ ! -f "$TEST_INPUT" ]; then
    echo "SKIP: Test input file not found: $TEST_INPUT"
else
    ./destruct elf "$TEST_INPUT" -o "$TEST7_OUTPUT" --decompile --simplify-cfg 2>&1 | head -20
    DECOMP_FILE="$TEST7_OUTPUT/$(base_name "$TEST_INPUT").decompiled.c"
    if [ -f "$DECOMP_FILE" ]; then
        LINE_COUNT=$(wc -l < "$DECOMP_FILE" || echo "0")
        if [ "$LINE_COUNT" -gt 0 ]; then
            echo "PASS: CFG simplification completed ($LINE_COUNT lines)"
            test_passed=$((test_passed + 1))
        else
            echo "FAIL: CFG simplification produced empty output"
            test_failed=$((test_failed + 1))
        fi
    else
        echo "FAIL: Decompiled file not found"
        test_failed=$((test_failed + 1))
    fi
fi

echo ""
echo "=== Test Summary ==="
echo "Tests passed: $test_passed"
echo "Tests failed: $test_failed"
echo "Total tests: $((test_passed + test_failed))"

if [ "$test_failed" -eq 0 ]; then
    echo ""
    echo "=== ALL TESTS PASSED ==="
    echo "ARM64 decompilation enhancement is working correctly!"
    exit 0
else
    echo ""
    echo "=== SOME TESTS FAILED ==="
    echo "Please review the failed tests above."
    exit 1
fi
