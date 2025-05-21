# SAP Audit Tool

A Python-based tool for analyzing SAP log data (SM20, CDHDR, CDPOS) to identify high-risk activities performed by third-party vendors using firefighter IDs (FF_*).

## Overview

This tool correlates activities across different SAP logs, evaluates their risk level, and produces a well-structured Excel output for audit review. It focuses on identifying high-risk activities such as:

- Debugging with data changes
- Direct table maintenance
- Configuration changes
- Code modifications
- Job scheduling changes
- Change-related RFC calls

## Features

- **Robust File Loading**: Comprehensive error handling and validation for input files
- **Flexible Column Mapping**: Configurable column names to adapt to different SAP system exports
- **Efficient Correlation**: Uses pandas.merge_asof for time-based correlation of events
- **Advanced Risk Assessment**: Detailed risk classification with specific rationales
- **Special Detection**: Identifies cases where SM20 shows display-only activity but CDHDR/CDPOS indicates changes
- **Comprehensive Output**: Formatted Excel workbook with three tabs (correlated events, unmatched SM20 logs, unmatched change documents)

## Requirements

- Python 3.6+
- pandas
- xlsxwriter

## Installation

1. Clone this repository or download the script
2. Install required packages:

```bash
pip install pandas xlsxwriter
```

## Usage

1. Prepare your SAP log data:
   - SM20 Security Audit Log export
   - CDHDR Change Document Header export
   - CDPOS Change Document Item export

2. Update the file paths in the script:

```python
SM20_FILE = "./input/feb_sm20_FF.xlsx"
CDHDR_FILE = "./input/feb_CDHDR_FF.xlsx"
CDPOS_FILE = "./input/feb_CDPOS_FF.xlsx"
OUTPUT_FILE = "./SAP_Audit_Report.xlsx"
```

3. Run the script:

```bash
python sap_audit_tool.py
```

4. Review the generated Excel report

## Configuration

The script includes several configurable parameters:

- **CORRELATION_WINDOW_MINUTES**: Time window (in minutes) for correlating events (default: 15)
- **Column Name Mapping**: Variables for mapping column names in your SAP exports
- **Date/Time Format**: Format string for parsing date and time values

## Output

The tool generates an Excel workbook with three tabs:

1. **Correlated_Events**: Events that were successfully correlated across logs with risk assessment
2. **Unmatched_CD_Changes**: Change documents that couldn't be correlated with SM20 logs
3. **Unmatched_SM20_Logs**: SM20 logs that couldn't be correlated with change documents

## Risk Assessment

Events are classified into three risk levels:

- **High Risk**: Activities requiring immediate follow-up; changes to critical components
- **Medium Risk**: Standard changes to sensitive areas
- **Low Risk**: Routine changes following normal procedures

## Customization

You can customize the risk assessment by modifying:

- `get_sensitive_tables()`: Add or remove tables considered sensitive
- `get_sensitive_tcodes()`: Add or remove transaction codes considered sensitive
- `expanded_risk_tag()`: Modify the risk assessment logic

## Future Enhancements

- External configuration file
- Command-line arguments
- Session analysis capability
- Integration with helpdesk tickets
- Web interface or GUI