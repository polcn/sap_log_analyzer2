# Dynamic Variable Field Handling

This document describes the enhanced field mapping capabilities added to the SAP Audit Tool to handle dynamic variable fields in SAP logs.

## Problem Description

SAP SM20 logs contain variable fields whose names can change across different exports due to:

1. **Event Mix**: Placeholder columns are only created when populated in at least one record
2. **ALV Layout**: Users can hide/rename columns before export
3. **Patch Level / Language**: SAP occasionally renames column texts when harmonizing field catalogs
4. **Language**: Column texts are language-dependent (e.g., German user sees "Transaktion" instead of "TCode")

This causes inconsistency in field names across different exports, leading to processing errors when specific columns like "VARIABLE DATA FOR MESSAGE" cannot be found.

## Solution Implemented

The SAP Audit Tool now includes comprehensive field mapping to handle these dynamic variations:

### 1. Field Mapping Dictionaries

The system maps various possible column names to canonical field names:

```python
field_mapping = {
    # Transaction code variations
    'TCODE': SM20_TCODE_COL,
    'TRANSACTION': SM20_TCODE_COL,
    'TRANSACTION CODE': SM20_TCODE_COL,
    
    # Variable field variations
    'FIRST VARIABLE': SM20_VAR_FIRST_COL,
    'VARIABLE 1': SM20_VAR_FIRST_COL,
    
    # Second variable/data field variations
    'VARIABLE 2': SM20_VAR_DATA_COL,  # In March extract
    'VARIABLE DATA': SM20_VAR_DATA_COL,  # In January extract
    'VARIABLE DATA FOR MESSAGE': SM20_VAR_DATA_COL,  # February extract
    
    # Third variable field
    'VARIABLE 3': SM20_VAR_DATA_COL  # Maps to VAR_DATA as per SAP behavior
}
```

### 2. Schema Consistency

The system now adds empty columns for any missing fields to ensure a consistent schema:

```python
# Add empty columns for any missing fields
for field in important_fields:
    if field not in df.columns:
        log_message(f"Warning: Important field '{field}' not found - adding empty column", "WARNING")
        df[field] = ""  # Add empty column
```

### 3. Mapping Application

The mapping is applied across all processors (SM20, CDHDR, CDPOS) ensuring consistent handling of variable fields.

## Benefits

This enhancement provides several key benefits:

1. **Robustness**: The system works correctly regardless of which export format is used
2. **Consistency**: Processing remains reliable even when column names vary between exports
3. **Reduced Errors**: Prevents failures due to missing fields
4. **Better Debug Detection**: Improves detection of debugging activities by properly mapping variable fields

## Technical Implementation

The changes are implemented in the following files:

- **sap_audit_data_prep.py**: Enhanced field mapping and empty column generation
- **SAP Log Session Merger.py**: Support for columns with different names
- **sap_audit_tool_risk_assessment.py**: Improved handling of variable data fields

## Example Mapping

| Month    | Original Column           | Mapped To                   | Notes                       |
|----------|---------------------------|----------------------------|----------------------------|
| January  | Variable Data             | VARIABLE DATA FOR MESSAGE   | Standardized to canonical name |
| February | VARIABLE DATA FOR MESSAGE | VARIABLE DATA FOR MESSAGE   | Already in canonical form   |
| March    | Variable 2                | VARIABLE DATA FOR MESSAGE   | Mapped to canonical name    |
| March    | Variable 3                | VARIABLE DATA FOR MESSAGE   | Third variable also mapped  |
