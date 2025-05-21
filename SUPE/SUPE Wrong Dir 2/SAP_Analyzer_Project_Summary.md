# SAP Log Analyzer Project Summary

## Repository Information

The SAP Log Analyzer tool is a Python-based application designed to analyze SAP security logs and change documents, identifying potential security risks and providing detailed audit reports.

- **Repository URL**: https://github.com/polcn/sap_log_analyzer2.git
- **Current Version**: 4.2.0 (April 2025)
- **Latest Feature**: Dynamic Variable Field Handling

## Project Overview

The SAP Log Analyzer was developed to help security teams and auditors efficiently review SAP user activities without requiring deep SAP technical knowledge. It processes security audit logs and change documents, creating a unified timeline with intelligent risk assessment that highlights potentially suspicious activities.

The tool is particularly valuable for:
- Security compliance reviews
- User activity auditing
- Change tracking in SAP systems
- Debugging pattern detection
- FireFighter access monitoring

## Key Components

The project consists of several Python scripts that work together:

1. **sap_audit_data_prep.py**: Prepares raw SAP export files for analysis
2. **SAP Log Session Merger.py**: Creates a unified timeline of user sessions
3. **sap_audit_tool_risk_assessment.py**: Evaluates risk levels of activities
4. **sap_audit_tool.py**: Main orchestration script
5. **sap_audit_tool_output.py**: Generates formatted Excel reports
6. **find_missing_descriptions.py**: Scans for fields without descriptions
7. **monitor_new_fields.py**: Detects fields missing descriptions
8. **update_sap_descriptions.py**: Maintains SAP element descriptions

## Documentation Files

The repository includes several documentation files:

1. **README.md**: 
   - High-level overview
   - Feature list
   - Installation requirements
   - Usage instructions
   - Benefits and capabilities

2. **SAP_Audit_Tool_Technical_Reference.md**:
   - Detailed architecture documentation
   - System components
   - Risk assessment methodology
   - Customization options
   - Troubleshooting guidance
   - Performance considerations
   - Security notes

3. **FIELD_MONITORING_GUIDE.md**:
   - Instructions for monitoring field descriptions
   - Usage of field description tools
   - Best practices for maintaining descriptions
   - Examples and templates

4. **dynamic_field_handling.md** (NEW):
   - Documentation of the dynamic variable field handling feature
   - Problem description and solution
   - Field mapping approach
   - Schema consistency implementation
   - Benefits of the enhancement

## Recent Enhancements

The most recent enhancement (v4.2.0) added dynamic variable field handling to address inconsistent field naming in SAP exports. This feature ensures the tool works correctly regardless of variations in field names across different export formats, improving reliability and reducing errors.

## Getting Started

To work with this project:

1. Clone the repository:
   ```
   git clone https://github.com/polcn/sap_log_analyzer2.git
   ```

2. Review the documentation files to understand the architecture and capabilities

3. Place SAP export files in the 'input' folder with the following naming patterns:
   - `*_sm20_*.xlsx` - Security audit log exports
   - `*_cdhdr_*.xlsx` - Change document header exports
   - `*_cdpos_*.xlsx` - Change document item exports

4. Run the data preparation script to process input files:
   ```
   python sap_audit_data_prep.py
   ```

5. Run the main tool to generate the audit report:
   ```
   python sap_audit_tool.py
   ```

6. Review the comprehensive report in `SAP_Audit_Report.xlsx`
