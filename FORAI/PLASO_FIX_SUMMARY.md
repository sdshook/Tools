# FORAI Plaso Processing Fix

## Problem Description

The FORAI script was failing when processing plaso files due to an error in the plaso library's Windows Event Log formatting code. The specific error was:

```
AttributeError: 'NoneType' object has no attribute 'GetAttributeContainers'
```

This occurred in the `winevt_rc.py` file when trying to process Windows Event Logs using the `l2tcsv` output format.

## Root Cause Analysis

1. **Primary Issue**: The script was trying to use the `l2tcsv` format first, which has known limitations and was causing a crash in the plaso library
2. **Format Limitations**: The error message explicitly stated that `l2tcsv` "has significant limitations" and recommended using the "dynamic" format instead
3. **Error Handling**: The original fallback logic couldn't execute because the process crashed before reaching the fallback code

## Solution Implemented

### 1. Format Priority Reordering
Changed the processing order to try formats in order of reliability:
- **First**: `dynamic` format (recommended by plaso)
- **Second**: `json` format (reliable structured data)
- **Third**: `l2tcsv` format (fallback with known limitations)

### 2. Improved Error Handling
- Added proper exception handling for `subprocess.TimeoutExpired`
- Added general exception handling for unexpected errors
- Added specific error messages for different failure scenarios
- Added timeout handling (1 hour per format attempt)
- **NEW**: Added specific `AttributeError` handling for Windows Event Log issues
- **NEW**: Added last format detection with helpful error messages
- **NEW**: Wrapped processing function calls in try-catch to prevent crashes

### 3. Better Logging
- Format-specific success/failure messages
- Performance metrics preserved for successful processing
- Chain of custody logging maintained
- Cleanup of temporary files on success

### 4. Parameter Handling Fix
- Fixed function parameter passing for different processing methods
- `_process_csv_timeline()` takes only the file path
- `_process_dynamic_timeline()` and `_process_json_timeline()` take file path and custom_module

### 5. Warning Suppression
- Added suppression for the fpdf2/PyFPDF conflict warning that was cluttering the output

## Code Changes Made

### Main Changes in `import_plaso_file()` method:

```python
# OLD: Tried l2tcsv first, then fallback
psort_cmd = [psort_cmd_path, "-o", "l2tcsv", ...]

# NEW: Try formats in order of preference
formats_to_try = [
    ("dynamic", f"{self.case_id}_timeline.txt", self._process_dynamic_timeline),
    ("json", f"{self.case_id}_timeline.json", self._process_json_timeline),
    ("l2tcsv", f"{self.case_id}_timeline.csv", self._process_csv_timeline)
]

for format_name, output_filename, process_func in formats_to_try:
    # Try each format with proper error handling
    try:
        result = subprocess.run(psort_cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode == 0 and output_path.exists():
            # Process with appropriate parameters
            if format_name == "l2tcsv":
                success = process_func(output_path)
            else:
                success = process_func(output_path, custom_module)
            if success:
                return True
    except subprocess.TimeoutExpired:
        # Handle timeout
    except Exception as e:
        # Handle other errors
```

## Expected Behavior After Fix

1. **First Attempt**: Try `dynamic` format (most likely to succeed)
2. **If Dynamic Fails**: Try `json` format (good structured data)
3. **If JSON Fails**: Try `l2tcsv` format (last resort)
4. **Better Error Messages**: Clear indication of which format failed and why
5. **No More Crashes**: Proper exception handling prevents script termination even if l2tcsv fails with AttributeError
6. **Helpful Guidance**: When all formats fail, users get specific guidance on next steps
7. **Clean Output**: fpdf warning suppressed

## Testing

The fix has been tested with a validation script that confirms:
- ✅ Format order is correct (dynamic → json → l2tcsv)
- ✅ Error handling is properly implemented
- ✅ Performance metrics are preserved
- ✅ All processing functions are called with correct parameters

## Usage

The fix is transparent to users. The same command that was failing should now work:

```bash
python FORAI.py --case-id CASE001 --plaso-file "CASE001_timeline.plaso" --llm-folder "D:\FORAI\llm" --keywords-file "D:\FORAI\keywords.txt" --autonomous-analysis --report pdf --chain-of-custody --output-dir "D:\FORAI\reports" --verbose
```

The script will now automatically try the most reliable format first and fall back to others if needed, with clear logging about which format succeeded.