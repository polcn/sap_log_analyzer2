#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored) - Part 2: Utility Functions
"""

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def validate_file_exists(file_path):
    """Validate that a file exists and is readable."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")
    return True

def validate_csv_file(file_path, required_columns):
    """
    Validate that a CSV file contains the required columns.
    Returns the DataFrame if valid.
    """
    try:
        # First check if file exists
        validate_file_exists(file_path)
        
        # Try to read the CSV file
        log_message(f"Reading CSV file: {file_path}")
        df = pd.read_csv(file_path, encoding='utf-8-sig')
        
        # Check for required columns (already in UPPERCASE from data prep)
        missing_columns = []
        for req_col in required_columns:
            if req_col not in df.columns.tolist():
                missing_columns.append(req_col)
                
        if missing_columns:
            raise ValueError(
                f"Missing required columns in {os.path.basename(file_path)}: {', '.join(missing_columns)}\n"
                f"Actual columns: {', '.join(df.columns.tolist())}"
            )
        
        return df
    except Exception as e:
        log_message(f"Error validating CSV file {file_path}: {str(e)}", "ERROR")
        raise

def load_session_timeline():
    """
    Load the session timeline Excel file produced by the SAP Log Session Merger.
    Returns the DataFrame if successful, None otherwise.
    """
    try:
        # Check if the session timeline file exists
        if not os.path.exists(SESSION_TIMELINE_FILE):
            log_message(f"Session timeline file not found: {SESSION_TIMELINE_FILE}", "WARNING")
            return None
            
        log_message(f"Loading session timeline from: {SESSION_TIMELINE_FILE}")
        
        # Load the Excel file
        timeline_df = pd.read_excel(SESSION_TIMELINE_FILE, sheet_name="Session_Timeline")
        
        # Verify required columns
        required_cols = [SESSION_ID_WITH_DATE_COL, SESSION_USER_COL, SESSION_DATETIME_COL, SESSION_SOURCE_COL]
        missing_cols = [col for col in required_cols if col not in timeline_df.columns]
        
        if missing_cols:
            log_message(f"Missing required columns in session timeline: {', '.join(missing_cols)}", "WARNING")
            return None
            
        log_message(f"Loaded session timeline with {len(timeline_df)} records")
        return timeline_df
        
    except Exception as e:
        log_message(f"Error loading session timeline: {str(e)}", "ERROR")
        return None
