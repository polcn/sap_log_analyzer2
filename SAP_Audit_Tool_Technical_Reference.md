# SAP Audit Tool Technical Guide

## Architecture Overview

The SAP Audit Tool consists of several interconnected components designed to process and analyze SAP security logs and change documents. The system follows a modular architecture with clear separation of concerns:

```
┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│                  │     │                   │     │                  │
│  Raw SAP Exports ├────►│  Data Preparation ├────►│  Session Merger  │
│                  │     │                   │     │                  │
└──────────────────┘     └───────────────────┘     └─────────┬────────┘
                                                             │
┌──────────────────┐     ┌───────────────────┐     ┌─────────▼────────┐
│                  │     │                   │     │                  │
│  Excel Reports   │◄────┤  Report Generator │◄────┤  Risk Assessment │
│                  │     │                   │     │                  │
└──────────────────┘     └───────────────────┘     └──────────────────┘
```

### Data Flow

1. **Input**: Raw SAP exports (SM20 audit logs, CDHDR change document headers, CDPOS change document items)
2. **Processing**: 
   - Data standardization (column headers, datetime formatting)
   - Session correlation and timeline creation
   - Risk assessment based on predefined rules
3. **Output**: Excel report with color-coded risk assessments and filtering capabilities

## System Components

### 1. Data Preparation (sap_audit_data_prep.py)

This module handles the initial processing of raw SAP export files:

- **Functions**:
  - `process_sm20()`: Processes SM20 security audit log exports
  - `process_cdhdr()`: Processes CDHDR change document header exports
  - `process_cdpos()`: Processes CDPOS change document item exports
  - `clean_whitespace()`: Utility function to clean string columns

- **Input Format**: Excel files with specific naming patterns:
  - `*_sm20_*.xlsx` - Security audit log exports
  - `*_cdhdr_*.xlsx` - Change document header exports 
  - `*_cdpos_*.xlsx` - Change document item exports

- **Dynamic Field Handling**:
  - Field mapping dictionaries to handle varying column names
  - Support for different variable field naming patterns
  - Auto-generation of empty columns for consistent schema
  - See detailed documentation in `dynamic_field_handling.md`

- **Output Format**: CSV files with standardized column names and data formats:
  - `SM20.csv` - Processed security audit logs
  - `CDHDR.csv` - Processed change document headers
  - `CDPOS.csv` - Processed change document items

### 2. Session Merger (SAP Log Session Merger.py)

This component correlates events across different log types into a unified session timeline:

- **Correlation Logic**:
  - Events are grouped by user
  - Temporal proximity is used to identify session boundaries
  - Activities within a threshold time window are considered part of the same session
  - TCode is used to associate change documents with SM20 logs

- **Session ID Generation**:
  - Sequential session IDs are assigned to each group of related activities
  - Format: `S0001 (YYYY-MM-DD)` where the date is the session start date

- **Output**: Excel file `SAP_Session_Timeline.xlsx` containing the unified session timeline

### 3. Risk Assessment (sap_audit_tool_risk_assessment.py)

This module analyzes the session timeline to identify security risks:

- **Risk Categories**:
  - Low: Normal operational activities
  - Medium: Activities with elevated privileges or sensitive data
  - High: Activities with significant security impact
  - Critical: Activities that indicate potential security violations

- **Risk Factors**:
  - Sensitive table access
  - Critical field modifications
  - Privileged transactions
  - Debugging activities
  - FireFighter account usage
  - Mass-change operations
  - Configuration alterations

- **Functions**:
  - `get_sensitive_tables()`: Returns list of security-sensitive tables
  - `get_critical_field_patterns()`: Returns patterns for critical fields
  - `get_sensitive_tcodes()`: Returns list of high-risk transaction codes
  - `assess_risk_session()`: Main function for risk assessment
  - `custom_field_risk_assessment()`: Assesses risk based on specific field changes

### 4. Main Orchestration (sap_audit_tool.py)

This is the main entry point that coordinates the entire process:

- **Functions**:
  - `load_session_timeline()`: Loads existing session timeline or returns None
  - `prepare_session_data()`: Prepares session data for risk assessment
  - `run_session_merger()`: Executes the session merger if needed
  - `main()`: Main execution function

- **Process Flow**:
  1. Check if session timeline exists
  2. If not, run the session merger
  3. Prepare session data for analysis
  4. Apply risk assessment to session data
  5. Generate Excel output

### 5. Report Generation (sap_audit_tool_output.py)

This component creates formatted Excel reports:

- **Sheets Generated**:
  - **Session_Timeline**: Chronological view of all user activities
  - **Correlated_Events**: (Legacy mode) Activities where audit log entries match change documents
  - **Unmatched_CD_Changes**: Change documents without corresponding audit log entries
  - **Unmatched_SM20_Logs**: Audit log entries without corresponding change documents
  - **Debug_Activities**: Special sheet for debugging and developer activities
  - **Summary**: Risk distribution statistics and charts
  - **Legend_Header_Colors**: Guide to the color-coding system

- **Functions**:
  - `apply_custom_headers()`: Formats worksheet headers based on data source
  - `generate_excel_output()`: Main function for Excel report generation

### 6. Field Description System

This subsystem maintains and applies business-friendly descriptions to technical SAP field names:

- **Components**:
  - `find_missing_descriptions.py`: Identifies fields without descriptions
  - `monitor_new_fields.py`: Continuously monitors for new fields
  - `update_sap_descriptions.py`: Updates the field description database

- **Database Structure**:
  - The field descriptions are stored in a SQLite database with the following schema:
    ```
    CREATE TABLE field_descriptions (
      field_name TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      last_updated DATETIME,
      source TEXT
    )
    ```

- **Integration**: Field descriptions are integrated into risk assessment and reporting to provide clear context for technical changes

## Risk Assessment Methodology

The risk assessment system uses a rule-based approach with the following factors:

### 1. Table Sensitivity

Tables are categorized by sensitivity level:

- **Critical**: Tables containing authorization data, security configurations
  - Examples: USR*, AGR*, USRAC, AUTH*

- **High Risk**: Tables containing sensitive master data or financial configurations
  - Examples: BKPF, BSEG, KNA1, LFA1, VBAK

- **Medium Risk**: Tables containing operational data with compliance implications
  - Examples: EKKO, EKPO, MKPF, MSEG

- **Low Risk**: Tables containing non-sensitive operational data
  - Examples: MAKT, MARA (depending on industry context)

### 2. Transaction Code Risk

Transaction codes are categorized by privilege level:

- **Critical**: Direct database modification, developer tools, authorization management
  - Examples: SE16, SA38, SU01, SE37, SE11, SE16N

- **High Risk**: System configuration, master data management
  - Examples: SPRO, MM01, XK01, FK01

- **Medium Risk**: Operational processes with compliance implications
  - Examples: ME21N, VA01, FB01

- **Low Risk**: Inquiry transactions, display-only access
  - Examples: MM03, VA03, FK03

### 3. Field Criticality

Fields are categorized by sensitivity:

- **Critical**: Fields affecting security, authorizations, or payment data
  - Examples: PASSWORD, BANKN, ACCNT, AUTH*

- **High Risk**: Fields affecting financial calculations or core business rules
  - Examples: BETRG (Amount), KBETR (Rate), ZTERM (Payment terms)

- **Medium Risk**: Fields affecting operational processes
  - Examples: MENGE (Quantity), DATUM (Date), UZEIT (Time)

- **Low Risk**: Descriptive fields
  - Examples: TEXT, DESCR, NAME*

### 4. Activity Type Analysis

Activities are analyzed based on type:

- **Create (I)**: New record creation is assessed based on table sensitivity
- **Update (U)**: Field modifications are assessed based on field criticality
- **Delete (D)**: Deletion is typically considered high risk for sensitive tables

### 5. Pattern Detection

The system detects special patterns indicating elevated risk:

- **Debugging**: Detection of debug sessions via specific variable markers
- **FireFighter**: Special monitoring for emergency access accounts
- **Mass Changes**: Detection of batch or mass update patterns
- **After-Hours Activity**: Activities outside normal business hours receive additional scrutiny

### 6. Scoring Algorithm

The final risk score is calculated using a weighted combination of the above factors:

```
Risk Score = (Table Sensitivity * 0.3) + 
             (TCode Risk * 0.3) + 
             (Field Criticality * 0.3) + 
             (Pattern Multiplier * 0.1)
```

The resulting score is mapped to risk levels:
- 0.0-0.3: Low Risk
- 0.3-0.6: Medium Risk
- 0.6-0.8: High Risk
- 0.8-1.0: Critical Risk

## Field Description System

The Field Description System translates technical SAP field names into business-friendly descriptions:

### 1. Detection Process

- **Automated Scanning**: The system automatically scans log files for field names
- **Comparison**: Field names are checked against the existing description database
- **Identification**: Fields without descriptions are flagged for review

### 2. Update Process

- **Manual Updates**: Administrators can add descriptions via the update tool
- **Batch Import**: Descriptions can be imported from CSV files
- **API Integration**: For advanced setups, descriptions can be retrieved from SAP via RFC

### 3. Implementation Details

- **Storage**: Descriptions are stored in a SQLite database for portability
- **Caching**: Frequently used descriptions are cached for performance
- **Versioning**: Description changes are tracked with timestamps

### 4. Field Description Format

Descriptions follow a standardized format:
- Clear, concise business terminology
- Context notes where appropriate
- Technical details for complex fields

Example:
```
KRED: "Vendor Account Number"
BUKRS: "Company Code"
BLDAT: "Document Date"
```

## Customization

### 1. Configuration Options

The tool can be customized through several mechanisms:

- **Risk Assessment Rules**:
  - Edit the risk assessment module to modify table and transaction risk levels
  - Add or modify field criticality patterns

- **Field Descriptions**:
  - Use the update tool to add or modify field descriptions
  - Import custom description sets for specialized business areas

- **Report Formatting**:
  - Modify the Excel formatting in the output module
  - Customize color schemes or add additional conditional formatting

### 2. Adding Custom Components

Developers can extend the system by:

- **Creating New Analyzers**: Add specialized analysis modules for specific business processes
- **Adding Data Sources**: Incorporate additional SAP log types
- **Creating Custom Reports**: Develop specialized reports for specific compliance needs

### 3. Integration Options

The tool can be integrated with:

- **Scheduling Systems**: Set up automated execution via Windows Task Scheduler or cron
- **Notification Systems**: Add email or messaging alerts for high-risk activities
- **Dashboarding Tools**: Export data for visualization in BI platforms

## Troubleshooting

### Common Issues

1. **Input File Format Issues**:
   - Ensure SAP exports follow the expected format
   - Check column headers in raw exports
   - Verify date/time formats in SAP extracts

2. **Session Correlation Problems**:
   - Adjust time window parameters if sessions aren't properly grouped
   - Check for clock synchronization issues between systems

3. **Risk Assessment Tuning**:
   - Review and adjust table sensitivity levels
   - Modify transaction code risk classifications
   - Update field criticality patterns

4. **Resource Limitations**:
   - For large datasets, increase memory allocation to Python
   - Consider processing logs in smaller time segments

### Logging

The system provides detailed logging:

- Console output shows processing status
- Log messages use timestamps and severity levels (INFO, WARNING, ERROR)
- Error messages include stack traces for debugging

### Version Compatibility

- The tool is designed for SAP ECC and S/4HANA logs
- The tool is compatible with Python 3.6 or higher
- Pandas 1.0.0 or higher is required for optimal performance

## Performance Considerations

- **File Size Impact**: Processing time scales linearly with input file size
- **Memory Usage**: Large datasets (>100,000 records) may require increased memory allocation
- **Optimization**: For very large datasets, consider:
  - Processing in batches by date range
  - Reducing the scope of sensitive table/field checks
  - Using SSD storage for temporary files

## Security Notes

 **Interpretation**: Risk assessments should be reviewed by qualified personnel
