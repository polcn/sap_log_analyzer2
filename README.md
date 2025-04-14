# SAP Log Analyzer

A tool for analyzing SAP logs and identifying security risks in user activities.

## Components

- **sap_audit_data_prep.py**: Prepares raw SAP export files for analysis
- **SAP Log Session Merger.py**: Creates a unified timeline of user sessions
- **sap_audit_tool_risk_assessment.py**: Evaluates risk levels of SAP activities
- **sap_audit_tool_output.py**: Generates formatted audit reports
- **sap_audit_tool.py**: Main orchestration script
- **find_missing_descriptions.py**: Identifies SAP elements without descriptions
- **update_sap_descriptions.py**: Helps maintain SAP element descriptions

## Features

- **Comprehensive Data Processing**: Prepares and correlates data from SM20, CDHDR, and CDPOS logs
- **User Session Timeline**: Creates a chronological view of user activities across log types
- **Intelligent Risk Assessment**: Evaluates security risks based on tables, fields, and transaction codes
- **Descriptive Risk Factors**: Provides detailed context for each flagged activity with SAP element descriptions
- **Detailed Excel Reports**: Generates formatted reports with risk highlighting and filtering

## Usage

1. Place SAP export files in the 'input' folder
2. Run `sap_audit_data_prep.py` to prepare the data
3. Run `sap_audit_tool.py` to generate the report
4. Review the results in `SAP_Audit_Report.xlsx`

## Maintenance

When new SAP elements appear in logs:

1. Run `update_sap_descriptions.py` to identify missing descriptions
2. Add missing descriptions to dictionaries in `sap_audit_tool_risk_assessment.py`
3. Run the tool again to generate reports with the new descriptions
