# Changelog

All notable changes to the SAP Log Analyzer will be documented in this file.

## [4.5.0] - May 2025

### Added
- New `OutputGenerator` class with Template Method pattern for different report formats
- Centralized `AuditController` class to orchestrate the entire audit workflow
- Pipeline architecture connecting all refactored modules
- Command-line interface with argument parsing for flexible usage
- Support for multiple output formats (Excel primary, with CSV option)
- Comprehensive validation between processing steps
- Progress tracking and reporting throughout the audit process
- Visualization capabilities for risk statistics
- Configuration validation at startup
- Support for different operating modes (full audit, data prep only, etc.)

### Changed
- Replaced hardcoded formatting with configuration-based templating
- Refactored SysAid integration with Strategy pattern for data sources
- Enhanced SysAid caching for performance optimization
- Improved error handling with retry mechanisms for API calls
- Made SysAid integration optional through configuration
- Updated main tool to use the new controller architecture
- Standardized error handling across all modules
- Enhanced command-line help documentation

### Fixed
- Fixed permissions issue with OneDrive synchronized files
- Improved error handling for locked files
- Enhanced data validation between processing steps
- Fixed SysAid column mapping issues
- Standardized error handling and logging
- Resolved issues with test data processing

## [4.4.0] - April 2025

### Added
- SysAid ticket integration with SAP log data
- New module `sap_audit_sysaid.py` to load and process SysAid ticket information
- Support for linking SAP activities to helpdesk tickets via "SysAid #" field
- Additional fields from SysAid tickets in reports (Title, Description, Notes, Request User, Process Manager, Request Time)
- Distinct color-coding for SysAid fields in Excel output (light purple)
- Updated legend in Excel output to include SysAid ticket information
- Comprehensive test suite for data preparation and SysAid integration modules
- Enhanced validation to ensure exact record counts in merged sessions

### Changed
- Modified data preparation to preserve "SysAid #" field in input files
- Enhanced Excel output to display and properly format SysAid ticket information
- Renamed SysAid description column to "SysAid Description" to avoid column name conflict with SAP log description

### Fixed
- Issue with duplicate Description columns by using distinct column names for SysAid tickets
- Improved NaN value handling in display output to prevent "nan" strings in reports
- Fixed indentation error in `sap_audit_data_prep.py` that was causing script execution to fail
- Enhanced function structure in data preparation module for better code organization
- Critical record count validation issue in SAP Log Session Merger
- CDPOS integration issues that caused records to be dropped or duplicated
- Index conflicts during DataFrame concatenation that affected record integrity
- Improved approach for merging SM20 and CDPOS records that preserves all source data

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
