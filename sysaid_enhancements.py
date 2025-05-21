#!/usr/bin/env python3
"""
SysAid Enhancement Script for SAP Log Analyzer

This script enhances the SysAid standardization and handling in the SAP Log Analyzer.
Key improvements:
1. Better standardization of SysAid numbers (handling various formats)
2. Enhanced session mapping with SysAid numbers
3. Detailed logging of SysAid processing

Based on the analysis of the project files, only a small percentage (0.3%) of rows
actually have SysAid values, but they represent critical change tickets.
"""

import re
import pandas as pd
from datetime import datetime
import os
import sys

# Configuration
DEBUG = True

def log_message(message, level="INFO"):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def standardize_sysaid(value):
    """
    Enhanced standardization of SysAid numbers.
    
    Properly handles:
    - Values with hash prefixes (#120,568)
    - Values with commas (120,568)
    - Values with SR/CR prefixes (SR-120568)
    - Plain numeric values (120568)
    - Empty or None values (returns "UNKNOWN")
    """
    if not value or pd.isna(value) or str(value).strip() == '':
        return "UNKNOWN"
    
    value = str(value).strip()
    
    # Log original value in debug mode
    if DEBUG:
        log_message(f"Standardizing SysAid: '{value}'", "DEBUG")
    
    # Remove hash prefix
    value = re.sub(r'^#', '', value)
    
    # Remove SR- or CR- prefixes
    value = re.sub(r'^(SR|CR)-', '', value)
    
    # Remove commas
    value = value.replace(',', '')
    
    # Log the standardized value in debug mode
    if DEBUG:
        log_message(f"Standardized to: '{value}'", "DEBUG")
    
    return value

def map_sessions_to_sysaid(df, session_col, sysaid_col):
    """
    Maps session IDs to SysAid values, ensuring proper standardization.
    
    For sessions with multiple SysAid values, prioritizes non-UNKNOWN values.
    """
    session_to_sysaid = {}
    
    # Get unique session IDs
    session_ids = df[session_col].unique()
    log_message(f"Mapping {len(session_ids)} unique sessions to SysAid values")
    
    for session_id in session_ids:
        subset = df[df[session_col] == session_id]
        sysaid_values = subset[sysaid_col].unique()
        
        # Standardize all SysAid values in this session
        std_values = [standardize_sysaid(val) for val in sysaid_values]
        unique_std_values = list(set(std_values))
        
        # If we have multiple values including UNKNOWN, prioritize non-UNKNOWN
        if len(unique_std_values) > 1 and "UNKNOWN" in unique_std_values:
            non_unknown = [val for val in unique_std_values if val != "UNKNOWN"]
            if non_unknown:
                session_to_sysaid[session_id] = non_unknown[0]
            else:
                session_to_sysaid[session_id] = "UNKNOWN"
        elif len(unique_std_values) == 1:
            session_to_sysaid[session_id] = unique_std_values[0]
        elif len(unique_std_values) > 1:
            # If multiple non-UNKNOWN values, take the most frequent
            value_counts = {}
            for val in std_values:
                if val != "UNKNOWN":
                    value_counts[val] = value_counts.get(val, 0) + 1
            
            if value_counts:
                most_common = max(value_counts.items(), key=lambda x: x[1])[0]
                session_to_sysaid[session_id] = most_common
            else:
                session_to_sysaid[session_id] = "UNKNOWN"
        else:
            session_to_sysaid[session_id] = "UNKNOWN"
    
    # Log the mapping results
    log_message(f"Session to SysAid mapping results:")
    unknown_count = sum(1 for v in session_to_sysaid.values() if v == "UNKNOWN")
    known_count = len(session_to_sysaid) - unknown_count
    log_message(f"  Total sessions: {len(session_to_sysaid)}")
    log_message(f"  Sessions with known SysAid: {known_count} ({known_count/len(session_to_sysaid)*100:.1f}%)")
    log_message(f"  Sessions with unknown SysAid: {unknown_count} ({unknown_count/len(session_to_sysaid)*100:.1f}%)")
    
    return session_to_sysaid

def detect_sysaid_column(df):
    """
    Auto-detect the SysAid column in a DataFrame.
    
    Looks for column names containing common SysAid patterns.
    """
    # Patterns to check (in order of priority)
    patterns = [
        'SYSAID#', 'SYSAID', 'TICKET#', 'TICKET', 
        'CR #', 'SR #', 'CR#', 'SR#', 
        'CHANGE REQUEST', 'CHANGE_REQUEST'
    ]
    
    # First check for exact matches (case-insensitive)
    for pattern in patterns:
        matches = [col for col in df.columns if pattern.upper() == col.upper()]
        if matches:
            log_message(f"Found SysAid column by exact match: {matches[0]}")
            return matches[0]
    
    # Then check for partial matches (case-insensitive)
    for pattern in patterns:
        matches = [col for col in df.columns if pattern.upper() in col.upper()]
        if matches:
            log_message(f"Found SysAid column by partial match: {matches[0]}")
            return matches[0]
    
    # If no direct matches, check for standalone CR or SR columns
    cr_matches = [col for col in df.columns if col.upper() == 'CR']
    sr_matches = [col for col in df.columns if col.upper() == 'SR']
    
    if cr_matches:
        log_message(f"Found SysAid column as CR: {cr_matches[0]}")
        return cr_matches[0]
    elif sr_matches:
        log_message(f"Found SysAid column as SR: {sr_matches[0]}")
        return sr_matches[0]
    
    log_message("No SysAid column found", "WARNING")
    return None

def process_timeline_file(file_path, output_path=None):
    """
    Process a timeline file to standardize SysAid values and map sessions.
    
    Returns the processed DataFrame and session mapping.
    """
    log_message(f"Processing timeline file: {file_path}")
    
    try:
        # Read the file
        df = pd.read_excel(file_path)
        log_message(f"Read file with {len(df)} rows and {len(df.columns)} columns")
        
        # Auto-detect columns
        session_col = next((col for col in df.columns if 'SESSION' in col.upper()), None)
        if not session_col:
            log_message("No session column found, cannot process file", "ERROR")
            return None, None
        
        sysaid_col = detect_sysaid_column(df)
        if not sysaid_col:
            log_message("No SysAid column found, cannot process SysAid mapping", "WARNING")
            return df, {}
        
        log_message(f"Using columns: Session='{session_col}', SysAid='{sysaid_col}'")
        
        # Standardize all SysAid values
        log_message("Standardizing SysAid values...")
        df['Standardized_SysAid'] = df[sysaid_col].apply(standardize_sysaid)
        
        # Map sessions to SysAid values
        session_to_sysaid = map_sessions_to_sysaid(df, session_col, sysaid_col)
        
        # Add a column with the mapped SysAid values
        df['Mapped_SysAid'] = df[session_col].map(session_to_sysaid)
        
        # Log statistics about the mapping
        unique_original = df[sysaid_col].nunique()
        unique_standardized = df['Standardized_SysAid'].nunique()
        unique_mapped = df['Mapped_SysAid'].nunique()
        
        log_message(f"Mapping statistics:")
        log_message(f"  Original unique SysAid values: {unique_original}")
        log_message(f"  Standardized unique SysAid values: {unique_standardized}")
        log_message(f"  Unique SysAid values after session mapping: {unique_mapped}")
        
        # Show the distribution of SysAid values
        value_counts = df['Mapped_SysAid'].value_counts()
        log_message("Distribution of mapped SysAid values:")
        for val, count in value_counts.items():
            percentage = (count / len(df)) * 100
            log_message(f"  {val}: {count} rows ({percentage:.2f}%)")
        
        # Save the processed file if an output path is provided
        if output_path:
            log_message(f"Saving processed file to: {output_path}")
            df.to_excel(output_path, index=False)
        
        return df, session_to_sysaid
        
    except Exception as e:
        log_message(f"Error processing file: {str(e)}", "ERROR")
        import traceback
        log_message(traceback.format_exc(), "ERROR")
        return None, None

def main():
    """Main function to process a timeline file."""
    # Set up command line arguments
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        # Default to looking in the script directory for timeline files
        script_dir = os.path.dirname(os.path.abspath(__file__))
        common_names = [
            "sap_session_timeline.xlsx",
            "SAP_Session_Timeline.xlsx",
            "timeline.xlsx",
            "sessions.xlsx"
        ]
        
        file_path = None
        for name in common_names:
            potential_path = os.path.join(script_dir, name)
            if os.path.exists(potential_path):
                file_path = potential_path
                log_message(f"Found timeline file: {name}")
                break
        
        if not file_path:
            log_message("No timeline file found. Please specify a file path.", "ERROR")
            return
        
        # Default output path
        output_filename = "enhanced_" + os.path.basename(file_path)
        output_path = os.path.join(script_dir, output_filename)
    
    # Process the file
    df, session_map = process_timeline_file(file_path, output_path)
    
    if df is not None:
        log_message("Processing completed successfully.")
        if output_path:
            log_message(f"Enhanced file saved to: {output_path}")
    else:
        log_message("Processing failed, see error messages above.", "ERROR")

if __name__ == "__main__":
    main()
