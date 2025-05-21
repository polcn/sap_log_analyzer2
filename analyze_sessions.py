import pandas as pd
from datetime import datetime

def log_message(message):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def analyze_sessions(file_path):
    """Analyze session distribution in the session timeline Excel file."""
    log_message(f"Reading Excel file: {file_path}")
    try:
        df = pd.read_excel(file_path)
        log_message(f"Successfully read file with {len(df)} rows")
        
        # Check for session column
        if 'Session ID with Date' in df.columns:
            session_col = 'Session ID with Date'
        else:
            log_message("Looking for session column...")
            session_cols = [col for col in df.columns if 'SESSION' in col.upper() and 'DATE' in col.upper()]
            if session_cols:
                session_col = session_cols[0]
                log_message(f"Found session column: {session_col}")
            else:
                log_message("No session column found", "ERROR")
                return
        
        # Analyze session distribution
        unique_sessions = df[session_col].nunique()
        log_message(f"Unique session IDs: {unique_sessions}")
        
        # Show session distribution
        session_counts = df[session_col].value_counts()
        log_message("Session distribution:")
        for session, count in session_counts.items():
            log_message(f"  {session}: {count} rows")
            
        # Analyze SysAid distribution
        sysaid_cols = [col for col in df.columns if 'SYSAID' in col.upper()]
        if sysaid_cols:
            sysaid_col = sysaid_cols[0]
            log_message(f"\nSysAid distribution (from {sysaid_col}):")
            sysaid_counts = df[sysaid_col].value_counts()
            for sysaid, count in sysaid_counts.items():
                log_message(f"  {sysaid}: {count} rows")
                
        # Analyze source distribution
        if 'Source' in df.columns:
            log_message("\nSource distribution:")
            source_counts = df['Source'].value_counts()
            for source, count in source_counts.items():
                log_message(f"  {source}: {count} rows")
                
    except Exception as e:
        log_message(f"Error analyzing file: {str(e)}")

if __name__ == "__main__":
    analyze_sessions("SAP_Session_Timeline.xlsx")
