# SAP Audit Tool Technical Reference

This technical reference provides an in-depth analysis of the SAP audit tool system, with particular focus on the evaluation logic. Use this document when troubleshooting the risk assessment functionality and understanding the overall workflow.

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Data Flow & Processing Pipeline](#data-flow--processing-pipeline)
3. [Script Detailed Analysis](#script-detailed-analysis)
4. [Risk Assessment Logic](#risk-assessment-logic)
5. [Configuration Parameters](#configuration-parameters)
6. [Troubleshooting Guide](#troubleshooting-guide)

## System Architecture

The SAP audit system consists of five Python scripts that work together in a modular pipeline:

```
Raw SAP Export Files 
       ↓
[sap_audit_data_prep.py]
       ↓
Standardized CSV Files (SM20.csv, CDHDR.csv, CDPOS.csv)
       ↓
[SAP Log Session Merger.py]
       ↓
Session Timeline (SAP_Session_Timeline.xlsx)
       ↓
[sap_audit_tool.py] → Imports modules for specialized functions
       ↓                ↙                       ↘
[sap_audit_tool_risk_assessment_updated.py]  [sap_audit_tool_output.py]
       ↓
Final Audit Report (SAP_Audit_Report.xlsx)
```

Each component has a specific role in transforming raw SAP log data into actionable audit insights.

## Data Flow & Processing Pipeline

### 1. Data Preparation Phase
- **Input**: Raw SAP export files (*_sm20_*.xlsx, *_cdhdr_*.xlsx, *_cdpos_*.xlsx)
- **Process**: Standardizes data by converting column headers to uppercase, creating datetime fields, and sorting by user and time
- **Output**: Three standardized CSV files (SM20.csv, CDHDR.csv, CDPOS.csv)

### 2. Session Merging Phase
- **Input**: Standardized CSV files from the preparation phase
- **Process**: Correlates events across different log types, assigns session IDs based on user activity with a 60-minute timeout
- **Output**: SAP_Session_Timeline.xlsx with unified, chronological view of activities

### 3. Risk Assessment Phase
- **Input**: Session timeline from the merging phase
- **Process**: Applies risk evaluation logic based on sensitive tables, critical fields, transaction codes, and change types
- **Output**: Session data with risk levels (High, Medium, Low) and documented risk factors

### 4. Output Generation Phase
- **Input**: Risk-assessed session data
- **Process**: Creates formatted Excel file with conditionally formatted risk levels and summary statistics
- **Output**: SAP_Audit_Report.xlsx with multiple sheets for different analysis views

## Script Detailed Analysis

### 1. sap_audit_data_prep.py

**Purpose**: Prepares and standardizes raw SAP log files for analysis.

**Key Functions**:
- `find_latest_file(pattern)`: Locates the most recent matching export file
- `process_sm20(input_file, output_file)`: Processes Security Audit Log data
- `process_cdhdr(input_file, output_file)`: Processes Change Document Header data
- `process_cdpos(input_file, output_file)`: Processes Change Document Item data

**Critical Processing Steps**:
- Converts column headers to UPPERCASE for consistent referencing
- Creates datetime columns by combining separate date and time fields
- Sorts data chronologically by user and datetime
- Validates presence of required fields and warns if missing
- Drops rows with invalid datetime values

**Error Handling**:
- Logs warnings for missing important fields
- Handles missing files gracefully with appropriate warnings
- Provides detailed error logs with timestamps

**Configuration Constants**:
- File patterns used to locate input files (SM20_PATTERN, CDHDR_PATTERN, CDPOS_PATTERN)
- Column name mappings for each file type
- Fields to exclude from processing (EXCLUDE_FIELDS)

### 2. SAP Log Session Merger.py

**Purpose**: Creates a unified timeline of user sessions by merging all log sources.

**Key Functions**:
- `assign_session_ids(df, user_col, time_col, session_timeout_minutes=60)`: Groups activities into sessions
- `prepare_sm20(sm20)` & `prepare_cdhdr(cdhdr)`: Formats source-specific data
- `merge_cdhdr_cdpos(cdhdr, cdpos)`: Joins change document headers with details
- `create_unified_timeline(sm20, cdhdr_cdpos)`: Combines all sources into a single timeline

**Session ID Logic**:
- A new session starts when:
  1. User changes, OR
  2. Time gap between activities exceeds 60 minutes
- Sessions are numbered chronologically (S0001, S0002, etc.)
- Each session ID includes the date for easier reference

**Data Correlation Strategy**:
- CDHDR and CDPOS are merged using:
  - Object class (OBJECTCLAS)
  - Object ID (OBJECTID)
  - Change document number (CHANGENR)
- SM20 records are correlated to change documents mainly by user and timestamp

**Output Formatting**:
- Color-coding by source (SM20, CDHDR, CDPOS)
- Column width optimized for content type
- Filter and frozen headers for usability

### 3. sap_audit_tool.py

**Purpose**: Main orchestration script that ties together all components.

**Workflow Logic**:
1. Checks if session timeline exists
2. If not, calls the SAP Log Session Merger functionality
3. Prepares session data for analysis
4. Imports and applies risk assessment module
5. Sorts results by risk level (High first)
6. Calls output generation module

**Analysis Preparation**:
- Adds flags for display-only activities
- Identifies actual changes (insertion, update, deletion)
- Flags special cases (e.g., display operations that included changes)

**Dependencies**:
- `sap_audit_tool_risk_assessment_updated.py`
- `sap_audit_tool_output.py`

### 4. sap_audit_tool_risk_assessment_updated.py

**Purpose**: Evaluates the risk level of SAP activities.

**Key Functions**:
- `get_sensitive_tables()`: Defines tables that contain security-critical data
- `get_critical_field_patterns()`: Defines regex patterns for sensitive fields
- `get_sensitive_tcodes()`: Defines transaction codes that involve high-risk operations
- `assess_risk_session(session_data)`: Main risk evaluation function for session-based analysis

**Risk Categories**:
- **High Risk**: Activities involving sensitive tables, fields, or transaction codes
- **Medium Risk**: Update operations not otherwise categorized as high risk
- **Low Risk**: Display-only operations with no changes

**Detailed Risk Evaluation Logic**:
See detailed breakdown in the [Risk Assessment Logic](#risk-assessment-logic) section.

### 5. sap_audit_tool_output.py

**Purpose**: Generates the final audit report Excel file.

**Key Functions**:
- `apply_custom_headers(worksheet, df, wb)`: Formats headers based on data source
- `generate_excel_output(...)`: Creates multi-sheet Excel report with formatting

**Output Structure**:
- **Session Timeline**: Unified view of all activity
- **Correlated Events**: Activities matched across log types (legacy mode)
- **Unmatched CD Changes**: Change documents without corresponding audit logs
- **Unmatched SM20 Logs**: Audit logs without change documents
- **Summary**: Risk distribution charts and statistics
- **Legend**: Explanation of color-coding scheme

**Formatting Features**:
- Conditional color-coding by risk level
- Header coloring by data source
- Auto-filters and frozen panes for usability
- Pie chart visualization of risk distribution

## Risk Assessment Logic

The heart of the audit tool is the risk assessment logic in `sap_audit_tool_risk_assessment_updated.py`. This section details the exact evaluation criteria.

### Risk Level Assignment Criteria

#### High Risk Indicators
An activity is assigned **HIGH RISK** if ANY of these conditions are met:

1. **Sensitive Table Access**:
   - The table being accessed/modified is in the sensitive tables list
   - Examples: USR01, AGR_USERS, BSEG, T012K, REGUH (see full list in code)

2. **Sensitive Transaction Code**:
   - The transaction code is in the sensitive tcodes list
   - Examples: 
     - Debugging: RSDEBUG, /H, ST22
     - User Management: SU01, SU10, PFCG
     - Table Maintenance: SE11, SE16N, SM30
     - Code Changes: SE38, SE80, SE24
     - Payment/Banking: F110, FBPM, FB70

3. **Critical Field Changes**:
   - The field name matches patterns for sensitive data
   - Patterns include:
     - Authentication: PASSWORD, AUTH, ROLE, PERMISSION
     - Financial: AMOUNT, CURRENCY, BANK, PAYMENT
     - Master Data: VENDOR, CUSTOMER, EMPLOYEE
     - System: CONFIG, SETTING, PARAMETER

4. **Display with Changes**:
   - Activity logged as display-only but change records exist
   - This catches potential security bypass attempts

5. **Insert or Delete Operations**:
   - Change indicator is 'I' (Insert) or 'D' (Delete)
   - These operations have higher impact than updates

#### Medium Risk Indicators
An activity is assigned **MEDIUM RISK** if:

1. **Update Operations**:
   - Change indicator is 'U' (Update)
   - Not already flagged as High Risk by other criteria

#### Low Risk Default
An activity is assigned **LOW RISK** if:
- None of the above conditions are met
- Typically these are display-only operations on non-sensitive data

### Risk Factor Documentation
For each identified risk, the specific factor is documented in the 'risk_factors' column:

- "Sensitive table; " - When a sensitive table is accessed
- "Sensitive transaction code; " - When a high-risk tcode is used
- "Critical field (Password field); " - When a sensitive field is changed
- "Display transaction with changes; " - When display actually includes changes
- "Insert operation; " - For record creation
- "Delete operation; " - For record deletion
- "Update operation; " - For record modification

### Configuration Lists

The risk assessment relies on three key configuration lists that define what is considered sensitive:

1. **Sensitive Tables** (from `get_sensitive_tables()`)
   - Security tables (USR01, AGR_USERS, etc.)
   - Payment and banking tables (REGUH, PAYR, etc.)
   - Financial tables (BKPF, BSEG, etc.)
   - Master data tables (KNA1, LFA1, etc.)

2. **Critical Field Patterns** (from `get_critical_field_patterns()`)
   - Regex patterns that match field names
   - Example: `r"(?i)PASS(WORD)?"` matches any field containing "pass" or "password"

3. **Sensitive Transaction Codes** (from `get_sensitive_tcodes()`)
   - Organized by category (debugging, user management, etc.)

## Configuration Parameters

These key configuration parameters affect the system behavior:

### sap_audit_data_prep.py
- `INPUT_DIR`: Directory for input files (default: "input" subfolder)
- `SM20_PATTERN`, `CDHDR_PATTERN`, `CDPOS_PATTERN`: File naming patterns
- Column name constants (e.g., `SM20_USER_COL`, `CDHDR_CHANGENR_COL`)
- `EXCLUDE_FIELDS`: Fields to skip in processing

### SAP Log Session Merger.py
- `SESSION_TIMEOUT_MINUTES`: Minutes of inactivity before starting a new session (default: 60)
- Column mapping for data sources

### sap_audit_tool.py
- `VERSION`: Tool version number
- `INPUT_DIR`: Directory for input files
- `OUTPUT_FILE`: Path for final report

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Missing Input Files
- **Symptom**: Data preparation script warns about missing files
- **Possible Causes**:
  - Files not placed in the expected "input" directory
  - Files don't match naming patterns (*_sm20_*.xlsx, etc.)
- **Solution**:
  - Check file naming conventions
  - Verify correct input directory path

#### 2. Risk Assessment Not Working
- **Symptom**: All activities show "Low" risk or "Risk assessment failed"
- **Possible Causes**:
  - Column name mismatches between data prep and risk assessment
  - Missing required columns in session timeline
- **Troubleshooting Steps**:
  1. Check column names in SAP_Session_Timeline.xlsx
  2. Verify column mappings in risk assessment module
  3. Look for errors in tool logs

#### 3. Sessions Not Properly Separated
- **Symptom**: Activities that should be separate appear in same session
- **Possible Cause**: SESSION_TIMEOUT_MINUTES too long
- **Solution**: Modify timeout value in SAP Log Session Merger.py

#### 4. Missing Critical Activities in Risk Assessment
- **Symptom**: Known risky operations not flagged appropriately
- **Possible Causes**:
  - Sensitive resource not included in configuration lists
  - Risk criteria not matching expected patterns
- **Solution**:
  - Update `get_sensitive_tables()`, `get_critical_field_patterns()`, or `get_sensitive_tcodes()`
  - Add additional risk assessment logic to `assess_risk_session()`

#### 5. Risk Evaluation Edge Cases
When troubleshooting risk assessment, pay attention to these special scenarios:

- **Mixed Source Analysis**: How records from different sources (SM20 vs CDPOS) are evaluated
- **Discrepancies Between Logs**: When SM20 shows one action but CDPOS indicates different action
- **Time Correlation Issues**: Events that appear related but have time stamp differences
- **Incomplete Data Records**: How the system handles records with missing fields

### Key Debugging Points

To deeply troubleshoot the evaluation logic:

1. **Risk Assessment Function**:
   - The `assess_risk_session()` function in sap_audit_tool_risk_assessment_updated.py is the central point for evaluation
   - Look for issues in how risk factors are applied and documented

2. **Session Timeline Creation**:
   - Check `create_unified_timeline()` in SAP Log Session Merger.py
   - This is where data from different sources gets combined and aligned

3. **Risk Configuration Lists**:
   - Verify sensitive tables, fields, and transaction codes match expectations
   - These lists determine what activities get flagged

4. **Column Mapping**:
   - Ensure column references match between modules
   - Check constants like `SESSION_TABLE_COL`, `SESSION_TCODE_COL` against actual data

5. **Risk Level Assignment Logic**:
   - Check conditional statements in risk assessment
   - Verify proper order of risk evaluation (higher risks should override lower)

## Extending the Risk Assessment

To enhance or modify the risk evaluation logic:

1. **Add New Sensitive Resources**:
   - Update `get_sensitive_tables()`, `get_critical_field_patterns()`, or `get_sensitive_tcodes()`
   - Follow existing patterns for consistency

2. **Add New Risk Criteria**:
   - Modify `assess_risk_session()` function
   - Add new conditions and document them in 'risk_factors'

3. **Change Risk Thresholds**:
   - Modify when activities are classified as High/Medium/Low
   - Example: Change update operations from Medium to High risk

4. **Custom Risk Combinations**:
   - Create compound conditions that look for specific patterns of behavior
   - Example: Flag when sensitive tables are accessed outside business hours
