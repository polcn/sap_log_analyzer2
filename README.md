# SAP Log Analyzer (v4.4.0)

## Project Overview

The SAP Log Analyzer is a Python-based security auditing tool that analyzes SAP security logs and change documents to identify security risks and provide detailed audit reports. It processes security audit logs (SM20) and change documents (CDHDR/CDPOS), creates a unified timeline, and applies risk assessment to highlight suspicious patterns.

## System Components

1. **Data Preparation** (`sap_audit_data_prep.py`)
   - Standardizes SAP export formats with flexible field mapping
   - Handles various column naming conventions across different SAP exports
   - Enhanced NaN value handling for cleaner output files
   - Robust error handling and whitespace cleaning
   - Preserves SysAid ticket references for helpdesk integration

2. **Session Merger** (`SAP Log Session Merger.py`)
   - Combines multiple log sources into a unified timeline
   - Creates calendar day-based user sessions for analysis

3. **Risk Assessment** (`sap_audit_tool.py`, `sap_audit_detectors.py`, `sap_audit_risk_core.py`)
   - Applies comprehensive security risk evaluation
   - Detects patterns of suspicious activity
   - Specialized detection for advanced debugging techniques

4. **Output Generation** (`sap_audit_tool_output.py`)
   - Creates formatted Excel reports with multiple analysis sheets

5. **Automated Analysis** (`sap_audit_analyzer.py`)
   - Automatically runs after audit processing completes
   - Analyzes results to identify key security concerns
   - Generates prioritized findings with follow-up recommendations
   - Creates both text summary and interactive HTML reports

## Recent Improvements

### v4.4.0 (April 2025)

#### SysAid Ticket Integration
- Added integration with SysAid helpdesk system to associate SAP activities with ticket information
- New module `sap_audit_sysaid.py` for loading and processing SysAid ticket data
- Support for linking SAP logs and change documents to helpdesk tickets via "SysAid #" field
- Enhanced reporting with helpdesk ticket context (title, description, notes, requestor, etc.)
- Color-coded SysAid fields in Excel reports for easy identification
- Provides business context for changes through associated ticketing system

### v4.3.0 (April 2025)

#### Automated Analysis and Reporting
- Added automated analysis that runs as the final step after processing
- Generates a text summary report (`SAP_Audit_Summary.txt`) with prioritized findings
- Creates an interactive HTML report (`SAP_Audit_Analysis.html`) with color-coded severity
- Provides specific follow-up recommendations for each high-risk finding
- Tracks detection algorithm improvements between runs

#### Enhanced Debugging Analysis
- Added detection for specific SAP message codes related to debugging (CU_M, CUL, BUZ, etc.)
- Implemented pattern detection for authorization bypass sequences (fail → debug → succeed)
- Added special focus on inventory valuation and potency changes during debugging sessions
- Can now identify sophisticated debugging patterns that might indicate security bypasses

#### Date-Based Session Definition
- Changed from 60-minute window to calendar day for session boundaries
- All user activity on the same day is now treated as a continuous session
- Enables detection of patterns that span several hours during a workday

#### Inventory Fraud Prevention
- Added specialized detection for debug-enabled changes to inventory tables and fields
- Focus on potency/valuation fields that could impact financial reporting
- Enhanced risk assessment specifically for material master and inventory movements

#### Multi-layered Detection Approach
- Combined individual event analysis with session-based pattern detection
- Integrated variable flag and message code detection approaches
- Enhanced stealth change detection with inventory-specific considerations

### v4.2.0 (Earlier Release)

#### Dual-Format Risk Descriptions
- Added improved risk descriptions using a consistent format: `[Plain English Summary]: [Technical Details]`
- Makes output more accessible to non-technical reviewers while preserving technical details

#### Enhanced Activity Type Classification
- Improved recognition of SE16 transactions with activity 02 (change) but no actual changes
- Better identification of authorization checks vs. actual changes
- Fixed issue with display activities sometimes being incorrectly marked as critical

#### Potential Stealth Changes Detection
- Added specific detection for SM20 entries with activity 02 (change) but no CDHDR/CDPOS records
- Flags these as "Potential unlogged changes" with medium risk level
- Provides clearer context about what this pattern means (possible changes through debugging)

#### Removed Account Type Special Handling
- Removed special handling for FireFighter accounts
- All privileged users are now evaluated using the same risk criteria

#### Risk Description Improvements
- Updated change indicator risk descriptions (Insert/Update/Delete)
- Enhanced default descriptions for low-risk items
- Added business context to all risk descriptions

## Current Capabilities

- Processes security audit logs (SM20) and change documents (CDHDR/CDPOS)
- Detects debugging activities using multiple techniques (flags message codes patterns)
- Identifies sophisticated patterns like authorization bypasses
- Applies special attention to inventory data changes (potency valuation)
- Identifies risky transactions sensitive field changes and system access patterns
- Generates comprehensive Excel reports with color-coded risk levels
- Works with variable SAP export formats and column naming conventions
- Provides clear dual-format risk descriptions for both technical and non-technical reviewers
- Identifies potential "stealth changes" where authorization exists but no change records found
- Integrates with SysAid ticketing system to provide business context for changes

## Documentation

- **Report Guide**: See [REPORT_GUIDE.md](REPORT_GUIDE.md) for detailed explanation of all report outputs, data sources, risk assessment methodologies, and how to interpret findings.

## Testing

The project includes comprehensive test suites for validating functionality:

1. **Data Preparation Testing** (`test_sap_audit_data_prep.py`)
   - Validates field mapping and column standardization
   - Tests NaN value handling and special character processing
   - Verifies flexible column name recognition

2. **SysAid Integration Testing** (`test_sap_audit_sysaid.py`)
   - Tests SysAid ticket data loading with different formats
   - Validates merging of ticket data with session timeline
   - Verifies Excel formatting of SysAid fields

3. **Results Validation Testing** (`test_sap_audit_results.py`)
   - Comprehensive end-to-end testing with known patterns
   - Validates risk assessment algorithms
   - Tests output file generation and content
   - Flexible testing framework for both test patterns and real data

4. **Running the Tests**
   - Execute individual test suites with: `python test_sap_audit_data_prep.py`
   - All tests are designed to be compatible with both synthetic test data and real-world SAP exports
