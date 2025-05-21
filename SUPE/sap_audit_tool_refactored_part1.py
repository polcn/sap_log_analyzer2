#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored)

This script analyzes SAP log data (SM20, CDHDR, CDPOS) to identify high-risk activities.
It can work with either:
1. Pre-processed CSV files with UPPERCASE column headers (legacy mode)
2. Session-based timeline from the SAP Log Session Merger (recommended)

Version: 4.0.0
Based on sap_audit_tool_3.0.0 with added support for session-based analysis.
"""

import sys
import os
import re
import time
from datetime import datetime, timedelta
import pandas as pd
import xlsxwriter

# --- Configuration ---
VERSION = "4.0.0"

# Get the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Script directory: {SCRIPT_DIR}")
print(f"Current working directory: {os.getcwd()}")

# File paths - can be overridden via command line arguments
if len(sys.argv) > 2:
    INPUT_DIR = sys.argv[1]
    OUTPUT_FILE = sys.argv[2]
else:
    # Default paths
    INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
    OUTPUT_FILE = os.path.join(SCRIPT_DIR, "SAP_Audit_Report.xlsx")

# Standard input file names (produced by data preparation script)
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Session timeline file (produced by SAP Log Session Merger)
SESSION_TIMELINE_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")

# Correlation window (minutes) for matching events
CORRELATION_WINDOW_MINUTES = 15

# Risk assessment configuration
HIGH_RISK_COLOR = '#FFC7CE'
MEDIUM_RISK_COLOR = '#FFEB9C'
LOW_RISK_COLOR = '#C6EFCE'

# --- Column Name Mapping (UPPERCASE) ---
# SM20 Security Audit Log columns
SM20_DATE_COL = 'DATE'
SM20_TIME_COL = 'TIME'
SM20_USER_COL = 'USER'
SM20_TCODE_COL = 'SOURCE TA'
SM20_MSG_COL = 'AUDIT LOG MSG. TEXT'
SM20_TERMINAL_COL = 'TERMINAL NAME'
SM20_CLIENT_COL = 'CL.'
SM20_SYSAID_COL = 'SYSAID#'
SM20_COMMENT_COL = 'COMMENT / REVIEW'

# CDHDR Change Document Header columns
CDHDR_DATE_COL = 'DATE'
CDHDR_TIME_COL = 'TIME'
CDHDR_USER_COL = 'USER'
CDHDR_TCODE_COL = 'TCODE'
CDHDR_CHANGENR_COL = 'DOC.NUMBER'
CDHDR_OBJECTCLAS_COL = 'OBJECT'
CDHDR_OBJECTID_COL = 'OBJECT VALUE'

# CDPOS Change Document Item columns
CDPOS_CHANGENR_COL = 'DOC.NUMBER'
CDPOS_TABNAME_COL = 'TABLE NAME'
CDPOS_CHNGIND_COL = 'CHANGE INDICATOR'
CDPOS_FNAME_COL = 'FIELD NAME'
CDPOS_TEXT_COL = 'TEXT FLAG'
CDPOS_VALUE_NEW_COL = 'NEW VALUE'
CDPOS_VALUE_OLD_COL = 'OLD VALUE'
CDPOS_AGING_COL = 'DATA AGING FILTER'

# Session Timeline columns (from SAP Log Session Merger)
SESSION_ID_COL = 'Session ID'
SESSION_ID_WITH_DATE_COL = 'Session ID with Date'
SESSION_USER_COL = 'User'
SESSION_DATETIME_COL = 'Datetime'
SESSION_SOURCE_COL = 'Source'
SESSION_TCODE_COL = 'TCode'
SESSION_TABLE_COL = 'Table'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'
SESSION_OLD_VALUE_COL = 'Old_Value'
SESSION_NEW_VALUE_COL = 'New_Value'
SESSION_DESCRIPTION_COL = 'Description'
SESSION_OBJECT_COL = 'Object'
SESSION_OBJECT_ID_COL = 'Object_ID'
SESSION_DOC_NUMBER_COL = 'Doc_Number'

# --- Date/Time Format ---
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'  # Matches '2025-03-10 19:17:23' format from input files
