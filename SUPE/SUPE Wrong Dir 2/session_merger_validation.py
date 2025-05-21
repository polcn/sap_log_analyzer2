#!/usr/bin/env python3
"""
SAP Log Session Merger Validation Script

This script adds record count validation to the session merger process.
It creates detailed logs of record counts at each processing stage to identify
why there may be discrepancies between input and output files.
"""

import os
import sys
import pandas as pd
from datetime import datetime

# Set paths based on the SAP Audit Tool structure
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
SESSION_TIMELINE_FILE = os.path.join(SCRIPT_DIR, "SAP_Session_Timeline.xlsx")
VALIDATION_LOG = os.path.join(SCRIPT_DIR, "session_merger_validation.log")

# Input files
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {level}: {message}"
    
    # Print to console
    print(log_entry)
    
    # Write to validation log
    try:
        with open(VALIDATION_LOG, 'a') as f:
            f.write(f"{log_entry}\n")
    except Exception as e:
        print(f"[{timestamp}] WARNING: Could not write to validation log: {str(e)}")

def analyze_sm20_file():
    """Analyze the SM20 input file."""
    try:
        # Check if file exists
        if not os.path.exists(SM20_FILE):
            log_message(f"SM20 file not found: {SM20_FILE}", "ERROR")
            return False
            
        # Load the CSV file
        df = pd.read_csv(SM20_FILE, encoding='utf-8-sig')
        record_count = len(df)
        
        log_message(f"SM20 File Analysis:", "INFO")
        log_message(f"  - Path: {SM20_FILE}", "INFO")
        log_message(f"  - Record count: {record_count}", "INFO")
        
        # Check for any invalid records
        null_date_count = df[df['DATE'].isna()].shape[0]
        null_time_count = df[df['TIME'].isna()].shape[0]
        
        if null_date_count > 0 or null_time_count > 0:
            log_message(f"  - Records with null date: {null_date_count}", "WARNING")
            log_message(f"  - Records with null time: {null_time_count}", "WARNING")
        
        return record_count
    except Exception as e:
        log_message(f"Error analyzing SM20 file: {str(e)}", "ERROR")
        return None

def analyze_session_timeline():
    """Analyze the session timeline Excel file."""
    try:
        # Check if file exists
        if not os.path.exists(SESSION_TIMELINE_FILE):
            log_message(f"Session timeline file not found: {SESSION_TIMELINE_FILE}", "ERROR")
            return False
            
        # Load the Excel file
        df = pd.read_excel(SESSION_TIMELINE_FILE)
        total_records = len(df)
        
        log_message(f"Session Timeline Analysis:", "INFO")
        log_message(f"  - Path: {SESSION_TIMELINE_FILE}", "INFO")
        log_message(f"  - Total record count: {total_records}", "INFO")
        
        # Count by source
        if 'Source' in df.columns:
            source_counts = df['Source'].value_counts()
            for source, count in source_counts.items():
                log_message(f"  - {source} records: {count}", "INFO")
        
        # Count unique sessions
        if 'Session ID with Date' in df.columns:
            session_ids = df['Session ID with Date'].str.split(' ', n=1, expand=True)[0]
            unique_sessions = session_ids.nunique()
            log_message(f"  - Unique sessions: {unique_sessions}", "INFO")
            
            # Analyze sessions with multiple sources
            mixed_sources = 0
            for session in session_ids.unique():
                session_data = df[session_ids == session]
                if 'Source' in df.columns and len(session_data['Source'].unique()) > 1:
                    mixed_sources += 1
                    source_breakdown = session_data['Source'].value_counts().to_dict()
                    log_message(f"  - Session {session} has mixed sources: {source_breakdown}", "INFO")
            
            log_message(f"  - Sessions with mixed sources: {mixed_sources}", "INFO")
        
        return {
            'total': total_records,
            'by_source': source_counts.to_dict() if 'Source' in df.columns else {},
            'unique_sessions': unique_sessions if 'Session ID with Date' in df.columns else 0,
            'mixed_sources': mixed_sources if 'Session ID with Date' in df.columns else 0
        }
    except Exception as e:
        log_message(f"Error analyzing session timeline: {str(e)}", "ERROR")
        return None

def validate_record_counts():
    """Validate record counts between input and output files."""
    try:
        # Clear previous log file
        with open(VALIDATION_LOG, 'w') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: SAP Log Session Merger Validation Started\n")
        
        log_message("Starting SAP Log Session Merger validation...")
        
        # Analyze input files
        sm20_count = analyze_sm20_file()
        
        # Analyze output timeline
        timeline_data = analyze_session_timeline()
        
        if sm20_count is not None and timeline_data is not None:
            # Compare counts
            sm20_in_timeline = timeline_data['by_source'].get('SM20', 0)
            
            log_message("\nRecord Count Validation:", "INFO")
            log_message(f"  - SM20 input file: {sm20_count} records", "INFO")
            log_message(f"  - SM20 in timeline: {sm20_in_timeline} records", "INFO")
            
            if sm20_count != sm20_in_timeline:
                log_message(f"  - Discrepancy: {sm20_in_timeline - sm20_count} records (timeline - input)", "WARNING")
                if sm20_in_timeline < sm20_count:
                    log_message(f"  - Missing SM20 records: {sm20_count - sm20_in_timeline}", "ERROR")
                else:
                    log_message(f"  - Extra SM20 records: {sm20_in_timeline - sm20_count}", "WARNING")
            else:
                log_message(f"  - All SM20 records successfully preserved in timeline", "INFO")
            
            # Report on CDPOS records
            cdpos_in_timeline = timeline_data['by_source'].get('CDPOS', 0)
            log_message(f"  - CDPOS in timeline: {cdpos_in_timeline} records", "INFO")
            
            log_message(f"  - Total timeline records: {timeline_data['total']}", "INFO")
            
            # Conclusion
            if sm20_count == sm20_in_timeline:
                log_message("\nConclusion: The session merger is correctly preserving all SM20 records.", "INFO")
                log_message(f"The {cdpos_in_timeline} CDPOS records are correctly added to the timeline as additional records.", "INFO")
                log_message(f"This explains why the total timeline count ({timeline_data['total']}) exceeds the SM20 count ({sm20_count}).", "INFO")
            else:
                log_message("\nConclusion: There is a record count discrepancy that needs investigation.", "WARNING")
        
        log_message("\nValidation complete.", "INFO")
        
    except Exception as e:
        log_message(f"Error during validation: {str(e)}", "ERROR")
        return False
    
    return True

if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP LOG SESSION MERGER VALIDATION ".center(80, "*") + "\n"
    banner += " Validates record counts between input and output files ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    validate_record_counts()
