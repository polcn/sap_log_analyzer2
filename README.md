# SAP Log Analyzer

A tool for analyzing SAP logs and identifying security risks in user activities.

## Components

- **sap_audit_data_prep.py**: Prepares raw SAP export files for analysis
- **SAP Log Session Merger.py**: Creates a unified timeline of user sessions
- **sap_audit_tool_risk_assessment.py**: Evaluates risk levels of SAP activities
- **sap_audit_tool_output.py**: Generates formatted audit reports
- **sap_audit_tool.py**: Main orchestration script
- **find_missing_descriptions.py**: Identifies SAP elements without descriptions
- **monitor_new_fields.py**: Automated tool to detect fields missing descriptions
- **update_sap_descriptions.py**: Helps maintain SAP element descriptions

## Features

- **Comprehensive Data Processing**: Prepares and correlates data from SM20, CDHDR, and CDPOS logs
- **User Session Timeline**: Creates a chronological view of user activities across log types
- **Intelligent Risk Assessment**: Evaluates security risks based on tables, fields, and transaction codes
- **Descriptive Risk Factors**: Provides detailed context for each flagged activity with SAP element descriptions
- **Detailed Excel Reports**: Generates formatted reports with risk highlighting and filtering
- **Complete Field Coverage**: Maintains descriptions for all SAP fields to improve report clarity

## Usage

1. Place SAP export files in the 'input' folder
2. Run `sap_audit_data_prep.py` to prepare the data
3. Run `sap_audit_tool.py` to generate the report
4. Review the results in `SAP_Audit_Report.xlsx`

## Field Description System

The SAP Log Analyzer includes a comprehensive field description system that makes audit reports more valuable by providing plain-language descriptions of SAP technical fields.

### Benefits

- **Improved Report Clarity**: Technical SAP field names (like "KRED") are displayed with descriptions ("Vendor Account Number")
- **Reduced SAP Expertise Required**: Reviewers don't need to be SAP experts to understand the significance of changes
- **Consistent Analysis**: Standardized descriptions ensure consistent interpretation across reviews
- **Complete Coverage**: The system tracks and maintains descriptions for all fields appearing in logs

### Example

Instead of seeing:
```
Changed KRED 1005321
```

Reviewers see:
```
Changed KRED (Vendor Account Number) 1005321
```

## Maintaining Field Descriptions

The system includes tools to maintain field descriptions as new SAP logs are processed:

### Monitoring for New Fields

1. After processing new SAP logs, run:
   ```
   python monitor_new_fields.py
   ```

2. The tool will output:
   - The current field description coverage percentage
   - Any fields that lack descriptions
   - Templates for adding descriptions to the risk assessment module

### Adding New Field Descriptions

When new fields are detected:

1. Open `sap_audit_tool_risk_assessment.py`
2. Locate the `get_common_field_descriptions()` function
3. Add the new field descriptions to the appropriate category, using the format:
   ```python
   "FIELD_NAME": "Field Name - Description of its purpose",
   ```
4. Run `monitor_new_fields.py` again to verify 100% coverage

### Comprehensive Analysis

For more detailed analysis, use the enhanced find_missing_descriptions.py:

```
python find_missing_descriptions.py
```

This tool provides:
- Complete listing of all fields with frequency counts
- Coverage statistics by field type
- Identification of which fields have descriptions and which don't
