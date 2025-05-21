# SAP Audit Tool: Monthly Run Guide

This document provides a step-by-step procedure for the monthly execution of the SAP Audit Tool. Follow this checklist to ensure consistent and reliable processing each month.

## Pre-Run Preparation

### 1. File Collection

☐ Obtain the following SAP export files for the month:
   - SM20 Security Audit Log (`*_sm20_*.xlsx`)
   - CDHDR Change Document Headers (`*_cdhdr_*.xlsx`)
   - CDPOS Change Document Items (`*_cdpos_*.xlsx`)
   - SysAid ticket export (`*sysaid*.xlsx`) if available

### 2. File Placement

☐ Place all export files in the input directory:
   ```
   <script_directory>/input/
   ```

☐ Verify file names follow expected patterns:
   - SM20: Contains `sm20` in the filename
   - CDHDR: Contains `cdhdr` in the filename
   - CDPOS: Contains `cdpos` in the filename
   - SysAid: Contains `sysaid` in the filename

### 3. Environment Verification

☐ Verify Python environment is active (if using virtual environment)

☐ Ensure required Python packages are installed:
   ```
   pandas
   numpy
   xlsxwriter
   openpyxl
   ```

☐ Check disk space (at least 500MB free space recommended)

### 4. Previous Run Cleanup

☐ Archive previous month's output files if needed

☐ Clear log directory if it's getting too large:
   ```
   <script_directory>/logs/
   ```

## Running the Tool

### 1. Execute the Main Script

☐ Open a terminal or command prompt

☐ Navigate to the script directory:
   ```
   cd <script_directory>
   ```

☐ Run the main script:
   ```
   python sap_audit_tool.py
   ```

### 2. Monitor Progress

☐ Watch the console output for progress updates

☐ Note any warnings that appear during processing

☐ If the script stops with an error, refer to the Troubleshooting section below

### 3. Completion Verification

☐ Confirm successful completion message in the console

☐ Note the location of the output report file:
   ```
   <script_directory>/output/SAP_Audit_Report.xlsx
   ```

☐ Check that the session timeline file was created:
   ```
   <script_directory>/SAP_Session_Timeline.xlsx
   ```

## Post-Run Verification

### 1. Output File Inspection

☐ Open the SAP_Audit_Report.xlsx file

☐ Verify all expected sessions are present

☐ Check the record counts against source files:
   - Ensure SM20 records are present
   - Ensure CDHDR/CDPOS records are present
   - If SysAid was provided, verify ticket links are present

### 2. Data Quality Checks

☐ Verify no unassigned sessions (all should have a session ID)

☐ Check for any "Unknown" risk levels (indicates assessment failure)

☐ Ensure datetime values are present and formatted correctly

☐ Verify color coding is working in the Excel report

### 3. Risk Assessment Review

☐ Review high risk items first (sorted to the top)

☐ Check medium risk items for potential issues

☐ Validate risk descriptions are meaningful and accurate

### 4. Log Review

☐ Check the log file in the logs directory:
   ```
   <script_directory>/logs/sap_audit_YYYYMMDD_HHMMSS.log
   ```

☐ Review any WARNING or ERROR messages

☐ Verify record counts in the log match expectations

## Distributing the Report

☐ Save a copy of the report with the month and year in the filename:
   ```
   SAP_Audit_Report_<YYYY>_<MM>.xlsx
   ```

☐ Archive a copy in the designated location for audit history

☐ Distribute the report to the security/audit team as required

## Troubleshooting Common Issues

### No Data Found

If the script reports "No data found in input files":

1. Verify input files are in the correct location
2. Check file naming patterns match the expected patterns
3. Open input files to ensure they contain data
4. Check file permissions

### Missing Data Sources

If one or more data sources are missing from the output:

1. Verify all required input files are present
2. Check the logs for specific errors related to those files
3. Open input files to ensure they have the expected columns
4. Try running the data preparation step manually:
   ```
   python sap_audit_data_prep.py
   ```

### Session Merger Errors

If session merging fails:

1. Check the log for specific error messages
2. Verify the CSV files were created in the input directory
3. Look for column name mismatches or unexpected formats
4. Try running the session merger manually:
   ```
   python "SAP Log Session Merger.py"
   ```

### Risk Assessment Issues

If risk assessment seems incorrect or incomplete:

1. Check for ERROR messages in the logs
2. Verify the session timeline was created correctly
3. Look for unusual patterns in the data that might confuse the risk rules
4. If specific values are causing issues, check the reference data

### Excel Output Problems

If the Excel report has formatting issues:

1. Ensure xlsxwriter and openpyxl packages are installed
2. Check if the Excel file is currently open (preventing writing)
3. Verify there's enough disk space for creating the report
4. Try generating the report manually:
   ```
   python sap_audit_tool_output.py
   ```

## Support Information

If you encounter persistent issues:

1. Collect the following information:
   - Full log file
   - Input file names
   - Error messages from the console
   - Description of the issue

2. Contact the tool maintainer with this information

## Maintenance Schedule

☐ Quarterly: Review configuration settings in `sap_audit_config.py`

☐ Semi-annually: Clean up old log files and archive old reports 

☐ Annually: Check for script updates and new functionality
