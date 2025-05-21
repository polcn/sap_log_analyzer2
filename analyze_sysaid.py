import pandas as pd
from datetime import datetime

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def analyze_sysaid_values(file_path):
    """Analyze the SysAid values in a CSV file."""
    log_message(f"Reading file: {file_path}")
    try:
        df = pd.read_csv(file_path, encoding='utf-8-sig')
        log_message(f"Successfully read file with {len(df)} rows")
        
        # Check if SysAid column exists
        sysaid_cols = [col for col in df.columns if 'SYSAID' in col.upper()]
        if not sysaid_cols:
            log_message("No SysAid column found in file", "ERROR")
            return
            
        sysaid_col = sysaid_cols[0]
        log_message(f"Found SysAid column: {sysaid_col}")
        
        # Convert to string and analyze values
        df[sysaid_col] = df[sysaid_col].astype(str)
        
        # Count of NaN or empty values
        empty_vals = df[sysaid_col].isin(['nan', 'None', 'NULL', ''])
        empty_count = empty_vals.sum()
        log_message(f"Empty or NaN values: {empty_count} ({empty_count/len(df)*100:.2f}%)")
        
        # Get unique non-empty values
        non_empty = df[~empty_vals]
        unique_values = non_empty[sysaid_col].unique()
        log_message(f"Unique non-empty SysAid values: {len(unique_values)}")
        
        # Show the unique values
        for i, val in enumerate(unique_values):
            log_message(f"  Value {i+1}: '{val}'")
            
        # Show distribution
        value_counts = non_empty[sysaid_col].value_counts()
        log_message("Distribution of SysAid values:")
        for val, count in value_counts.items():
            log_message(f"  '{val}': {count} rows")
            
    except Exception as e:
        log_message(f"Error analyzing file: {str(e)}", "ERROR")

if __name__ == "__main__":
    analyze_sysaid_values(r"input\SM20.csv")
