import pandas as pd
import os
import re
from datetime import datetime

def log_message(message):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def standardize_sysaid(value):
    """Standardize SysAid numbers by removing prefixes and commas."""
    if not value or pd.isna(value) or str(value).strip() == '':
        return "UNKNOWN"
    
    value = str(value).strip()
    
    # Remove hash prefix
    value = re.sub(r'^#', '', value)
    
    # Remove SR- or CR- prefixes
    value = re.sub(r'^(SR|CR)-', '', value)
    
    # Remove commas
    value = value.replace(',', '')
    
    return value

def analyze_timeline_file(file_path):
    """Analyze the session timeline Excel file for SysAid values."""
    log_message(f"Reading timeline file: {file_path}")
    
    try:
        df = pd.read_excel(file_path)
        log_message(f"Successfully read file with {len(df)} rows")
        
        # Check for session and SysAid columns
        session_col = next((col for col in df.columns if 'SESSION ID' in col.upper()), None)
        sysaid_col = next((col for col in df.columns if 'SYSAID' in col.upper()), None)
        
        if not session_col:
            log_message("No session column found")
            return
            
        if not sysaid_col:
            log_message("No SysAid column found")
            return
            
        log_message(f"Found session column: {session_col}")
        log_message(f"Found SysAid column: {sysaid_col}")
        
        # Get unique SysAid values
        sysaid_values = df[sysaid_col].unique()
        log_message(f"Found {len(sysaid_values)} unique raw SysAid values")
        
        # Standardize SysAid values
        standardized_values = [standardize_sysaid(val) for val in sysaid_values]
        unique_standardized = set(standardized_values)
        log_message(f"After standardization: {len(unique_standardized)} unique values")
        
        # Show all unique values
        log_message("All standardized SysAid values:")
        for i, val in enumerate(sorted(unique_standardized)):
            log_message(f"  {i+1}. {val}")
            
        # Analyze session distribution
        session_counts = df[session_col].value_counts()
        log_message("\nSession distribution:")
        for session, count in session_counts.items():
            log_message(f"  {session}: {count} rows")
            
        # Map sessions to SysAid values
        session_to_sysaid = {}
        for session_id in df[session_col].unique():
            subset = df[df[session_col] == session_id]
            sysaids = subset[sysaid_col].unique()
            # Take the most common non-UNKNOWN value if multiple exist
            if len(sysaids) > 1 and "UNKNOWN" in [standardize_sysaid(s) for s in sysaids]:
                non_unknown = [s for s in sysaids if standardize_sysaid(s) != "UNKNOWN"]
                if non_unknown:
                    session_to_sysaid[session_id] = standardize_sysaid(non_unknown[0])
                else:
                    session_to_sysaid[session_id] = "UNKNOWN"
            else:
                session_to_sysaid[session_id] = standardize_sysaid(sysaids[0])
                
        log_message("\nSession to SysAid mapping:")
        for session, sysaid in session_to_sysaid.items():
            log_message(f"  {session} -> {sysaid}")
            
        # Output session count percentages
        total_sessions = sum(session_counts.values)
        log_message("\nSession distribution percentages:")
        for session, count in session_counts.items():
            percentage = (count / total_sessions) * 100
            log_message(f"  {session}: {count} rows ({percentage:.1f}%)")
        
    except Exception as e:
        log_message(f"Error analyzing timeline file: {str(e)}")

if __name__ == "__main__":
    # Look for timeline files in the current directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check for common timeline file names
    potential_files = [
        "SAP_Session_Timeline.xlsx",
        "sap_session_timeline.xlsx",
        "Timeline.xlsx",
        "timeline.xlsx",
        "sessions.xlsx",
        "SAP_Sessions.xlsx"
    ]
    
    # Also look for any Excel files with "timeline" or "session" in the name
    all_files = [f for f in os.listdir(script_dir) if f.endswith('.xlsx')]
    timeline_files = [f for f in all_files if 'timeline' in f.lower() or 'session' in f.lower()]
    
    # Combine and remove duplicates
    all_timeline_files = list(set(potential_files + timeline_files))
    
    # Try to analyze each potential file
    found_file = False
    for file_name in all_timeline_files:
        file_path = os.path.join(script_dir, file_name)
        if os.path.exists(file_path):
            log_message(f"Found potential timeline file: {file_name}")
            try:
                analyze_timeline_file(file_path)
                found_file = True
                # Break after successfully analyzing the first file
                break
            except Exception as e:
                log_message(f"Error analyzing {file_name}: {str(e)}")
    
    if not found_file:
        log_message("No timeline files found. Please specify the path to the timeline file.")
        
        # List all Excel files as alternatives
        excel_files = [f for f in os.listdir(script_dir) if f.endswith('.xlsx') or f.endswith('.xls')]
        if excel_files:
            log_message("Available Excel files:")
            for i, file in enumerate(excel_files):
                log_message(f"  {i+1}. {file}")
            
            # Prompt user for input
            log_message("\nTo analyze a specific file, run:")
            log_message(f"python count_sysaid_in_timeline.py <filename>")
