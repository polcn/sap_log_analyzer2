# Changelog

All notable changes to the SAP Log Analyzer will be documented in this file.

## [4.3.0] - April 2025

### Added
- New `sap_audit_analyzer.py` module for automated analysis of audit results
- Automatic generation of text summary report (`SAP_Audit_Summary.txt`)
- Interactive HTML report with color-coded risk levels (`SAP_Audit_Analysis.html`)
- Prioritized follow-up recommendations for high-risk findings
- Session information display for all users in reports
- Tracking of detection algorithm improvements between runs

### Enhanced
- Improved detection of BU4 events (Dynamic ABAP code execution)
- Enhanced debugging pattern detection with flexible column matching
- Multi-field search for debug indicators across all columns
- Consistent formatting for all users in reports regardless of activity level
- Proper handling of NaN values displayed as "N/A" in reports

### Fixed
- Issue with missing session information for some users in reports
- Inconsistent display of activity types between different users
- NaN values appearing in report outputs instead of "N/A"
- JSON serialization issues in metadata tracking

## [4.2.0] - March 2025

### Added
- Dual-format risk descriptions with plain language and technical details
- Enhanced stealth change detection for activities with change permission but no change records
- Special focus on inventory-related tables and fields for fraud prevention

### Enhanced
- Improved recognition of SE16 transactions with activity code 02 (change) but no actual changes
- Better identification of authorization checks vs. actual changes
- Enhanced default descriptions for low-risk items with business context

### Changed
- Switched from 60-minute window to calendar day for session boundaries
- Removed special handling for FireFighter accounts
- All privileged users now evaluated using the same risk criteria

### Fixed
- Issue with display activities sometimes being incorrectly marked as critical
- Fixed variable field detection for inconsistent column naming
