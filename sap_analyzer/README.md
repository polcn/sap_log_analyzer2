# SAP Analyzer Package

A modular package for advanced analysis of SAP audit logs with SysAid ticket integration.

## Overview

The SAP Analyzer package provides a comprehensive set of tools for analyzing SAP audit logs. It extends the functionality of the SAP Audit Tool by adding more advanced analysis capabilities, SysAid ticket integration, and structured reporting.

## Features

- **Risk Distribution Analysis**: Analyzes the distribution of risk levels across audit events
- **High Risk Detection**: Identifies high-risk activities requiring follow-up
- **User Analysis**: Identifies users with suspicious activity patterns
- **Session Pattern Analysis**: Detects suspicious patterns within user sessions
- **Debug Activity Analysis**: Provides insights into debugging activities
- **SysAid Integration**: Enriches audit data with SysAid helpdesk ticket information
- **Performance Tracking**: Compares algorithm improvements across runs
- **Modular Architecture**: Well-organized codebase for easy maintenance and extension
- **Backward Compatibility**: Works with existing SAP Audit Tool infrastructure

## SysAid Integration

The analyzer now supports integration with SysAid helpdesk tickets. It can link audit events to their corresponding SysAid tickets and include relevant ticket information in reports:

- **Title**: Ticket title/summary
- **Description**: Detailed ticket description
- **Notes**: Additional ticket notes
- **Request User**: User who submitted the ticket
- **Process Manager**: Manager assigned to the ticket
- **Request Time**: When the ticket was submitted

## Package Structure

- **`__init__.py`**: Package initialization and exports
- **`utils.py`**: Utility functions for common operations
- **`analysis.py`**: Core analysis functions
- **`metadata.py`**: Metadata handling for performance tracking
- **`reporting.py`**: Report generation (text and HTML)
- **`run.py`**: Main entry points for running the analyzer

## Usage

### From the SAP Audit Tool

The analyzer is automatically invoked as the final step of the SAP Audit Tool:

```python
# In sap_audit_tool.py
from sap_audit_analyzer import run_analysis_from_audit_tool

# Run the analysis
run_analysis_from_audit_tool(OUTPUT_FILE)
```

### Standalone Usage

You can also run the analyzer directly using the provided script:

```bash
python run_sap_analyzer.py --report path/to/report.xlsx --sysaid path/to/sysaid.xlsx
```

Or import and use the package in your own code:

```python
from sap_analyzer.run import run_analysis

result = run_analysis(
    report_path="path/to/report.xlsx",
    summary_path="path/to/summary.txt",
    analysis_path="path/to/report.html",
    metadata_path="path/to/metadata.json",
    sysaid_path="path/to/sysaid.xlsx"
)
```

## Output

The analyzer generates two main outputs:

1. **Text Summary** (`SAP_Audit_Summary.txt`): A markdown-formatted summary of key findings
2. **HTML Report** (`SAP_Audit_Analysis.html`): A detailed HTML report with formatted sections and data visualization

## Dependencies

- Python 3.8+
- pandas
- json
- re (regular expressions)
