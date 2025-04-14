# SAP Field Monitoring Guide

This guide provides detailed instructions for using the SAP field description monitoring tools included with the SAP Log Analyzer. These tools help maintain 100% coverage of field descriptions in your audit reports.

## Overview

The SAP Log Analyzer includes two primary tools for field description monitoring:

1. **monitor_new_fields.py**: A streamlined tool for quick verification of field description coverage
2. **find_missing_descriptions.py**: A comprehensive analysis tool for deeper investigation

## When to Run Field Monitoring

We recommend running the field monitoring tools:

- After processing new SAP log files
- When updating the risk assessment module
- Before generating audit reports for critical reviews
- After adding new field descriptions to verify coverage

## Using monitor_new_fields.py

### Purpose
This tool quickly identifies any SAP fields in your session timeline that don't have descriptions, displays their frequency, and provides templates for adding them.

### Usage

```bash
python monitor_new_fields.py [path_to_timeline_file]
```

If no path is provided, the tool defaults to: `SAP_Session_Timeline.xlsx`

### Example Output: Complete Coverage

```
[2025-04-14 12:38:18] INFO: Analyzing file: C:\Users\craig\OneDrive\Documents\Python\SAP_Session_Timeline.xlsx
[2025-04-14 12:38:18] INFO: Loaded 9143 rows of data
[2025-04-14 12:38:18] INFO: Found 20 unique fields in the data
[2025-04-14 12:38:18] INFO: All fields have descriptions. No action needed.
[2025-04-14 12:38:18] INFO: Field description coverage: 100.0%
```

### Example Output: Missing Descriptions

```
[2025-04-14 12:37:15] INFO: Analyzing file: C:\Users\craig\OneDrive\Documents\Python\SAP_Session_Timeline.xlsx
[2025-04-14 12:37:15] INFO: Loaded 9143 rows of data
[2025-04-14 12:37:15] INFO: Found 20 unique fields in the data
[2025-04-14 12:37:15] WARNING: Detected 1 new fields without descriptions

New fields detected:
1. SPERM (0 occurrences)

Field description templates:
    "SPERM": "SPERM - [Add description here]",
[2025-04-14 12:37:15] INFO: Field description coverage: 95.0%
```

### Interpreting Results

- **Total unique fields**: The number of distinct field names found in the session timeline
- **Fields with/without descriptions**: Counts of fields that have descriptions and those that don't
- **Field description coverage**: Percentage of fields that have descriptions
- **New fields detected**: List of field names that require descriptions
- **Field description templates**: Ready-to-use templates that can be copied directly into the risk assessment module

## Using find_missing_descriptions.py

### Purpose
This tool performs a more comprehensive analysis, showing all fields (with and without descriptions) and their frequency in the data.

### Usage

```bash
python find_missing_descriptions.py
```

### Example Output

```
Reading file: C:\Users\craig\OneDrive\Documents\Python\SAP_Session_Timeline.xlsx
Total rows: 9143

Found 9 unique tables
Found 18 unique transaction codes
Found 20 unique fields

=== COMPREHENSIVE FIELD ANALYSIS ===

Total unique fields: 20
Fields with descriptions: 20
Fields without descriptions: 0

--- ALL FIELDS BY FREQUENCY ---
1. ZZ1_ORDEREDQTY_DLIU (1 occurrences) ✓ - Custom Ordered Quantity Delivery Unit
2. CAPA (0 occurrences) ✓ - Capacity
3. COO (0 occurrences) ✓ - Country of Origin
...

=== CHECKING FOR ALL VENDOR FIELDS ===
Records with KRED as field: 0
Records mentioning KRED in risk factors: 0
Records with KREDI as field: 0
...
```

### Interpreting Results

- **✓ symbol**: Indicates the field has a description
- **✗ symbol**: Indicates the field is missing a description
- **Fields by frequency**: Shows which fields appear most often in your data
- **Records mentioning fields**: Shows where fields appear in your data

## Adding New Field Descriptions

When you discover fields without descriptions:

1. Open `sap_audit_tool_risk_assessment.py`
2. Locate the `get_common_field_descriptions()` function
3. Find the appropriate section for your field type:
   - Authorization fields
   - User/account fields
   - Document fields
   - Financial fields
   - Sales fields
   - Purchase fields
   - Material fields
   - Status and control fields
   - Custom fields
4. Add the new field description using the format:
   ```python
   "FIELD_NAME": "Field Name - Description of its purpose",
   ```
5. Run `monitor_new_fields.py` again to verify 100% coverage

## Example: Adding Vendor Field Descriptions

Here's an example of adding vendor-related field descriptions:

```python
# Purchase fields
"EBELN": "Purchase Document Number - Identifies purchasing documents",
"LIFNR": "Vendor Number - Identifier for vendor account",
"KRED": "Vendor Account Number - Unique identifier for vendor master records",
"KREDI": "Alternate Vendor Account - Alternative vendor identification",
"KTOKK": "Vendor Account Group - Categorizes vendor accounts by type",
"XCPDK": "One-time Account Indicator - Identifies vendor as one-time account",
"EBELP": "Purchase Document Item - Line item in purchase document",
```

## Best Practices

- **Consistent Formatting**: Follow the "Field Name - Description" format
- **Meaningful Descriptions**: Provide context about what the field represents
- **Field Categorization**: Place fields in the appropriate category
- **Regular Monitoring**: Check for new fields after processing new log files
- **Maintain 100% Coverage**: Always aim for 100% field description coverage
