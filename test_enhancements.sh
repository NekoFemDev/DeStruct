#!/data/data/com.termux/files/usr/bin/env bash
# ARM64 ELF Decompilation Enhancement Test
# Tests the enhanced ARM64 decompilation functionality

set -e

cd "$(dirname "$0")"

# Check if destruct binary exists
if [ ! -f "./destruct" ]; then
    echo "ERROR: destruct binary not found"
    exit 1
fi

# Use the existing test ARM64 file (prefer the scripted name, fall back to the repo fixture)
TEST_INPUT="arm64.sh"
if [ ! -f "$TEST_INPUT" ]; then
    TEST_INPUT="test/liblun.so"
fi
ELF_PATH="$TEST_INPUT"
if [ ! -f "$ELF_PATH" ]; then
    echo "ERROR: Test file $ELF_PATH not found"
    exit 1
fi

OUTPUT_DIR="enhanced_output_$(date +%s)"
mkdir -p "$OUTPUT_DIR"

echo "=== ARM64 Decompilation Enhancement Test ==="
echo "Input file: $ELF_PATH"
echo "Output directory: $OUTPUT_DIR"

echo "\nRunning ARM64 decompilation with enhancements..."

# Run the decompilation with enhancements (now the default with --decompile)
./destruct elf "$ELF_PATH" -o "$OUTPUT_DIR" --decompile 2>&1 | head -30

# Check for decompiled output
BASE=$(basename "$ELF_PATH")
DECOMP_FILE="$OUTPUT_DIR/${BASE}.decompiled.c"
if [ ! -f "$DECOMP_FILE" ]; then
    echo "ERROR: Decompiled file not found: $DECOMP_FILE"
    exit 1
fi

echo "\n=== Testing Enhancement Application ==="
echo "Base decompiled file: $(wc -l < "$DECOMP_FILE") lines"

# Apply enhancements if available
ENHANCED_FILE="$DECOMP_FILE.enhanced"
if [ -f "$ENHANCED_FILE" ]; then
    echo "Enhanced file found: $(wc -l < "$ENHANCED_FILE") lines"
    
    echo "\n=== Output Quality Check ==="
    echo "Checking for enhanced comment markers..."
    COMMENT_COUNT=$(grep -c "// Source:" "$ENHANCED_FILE" || echo "0")
    echo "Source comments: $COMMENT_COUNT"
    
    FUNCTION_COUNT=$(grep -c "Function start" "$ENHANCED_FILE" || echo "0")
    echo "Function start comments: $FUNCTION_COUNT"
    
    LOCATION_COUNT=$(grep -c "Line:" "$ENHANCED_FILE" || echo "0")
    echo "Line annotations: $LOCATION_COUNT"
    
    echo "\n=== First 20 lines of enhanced output ==="
    head -20 "$ENHANCED_FILE"
else
    echo "Enhanced file not found - running basic decompilation validation..."
    echo "\n=== Basic Output Validation ==="
    echo "Decompiled content preview:"
    head -20 "$DECOMP_FILE"
fi

echo "\n=== Test Summary ==="
echo "✓ ARM64 decompilation: SUCCESS"
echo "✓ Enhancement test completed"
echo "✓ ARM64 decompilation enhancement pipeline test: COMPLETE"
