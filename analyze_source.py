import pandas as pd
from datetime import datetime

def log_message(message):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def analyze_source_file(file_path):
    """Analyze the source Excel file for SysAid values."""
    log_message(f"Reading source file: {file_path}")
    try:
        df = pd.read_excel(file_path)
        log_message(f"Successfully read file with {len(df)} rows and {len(df.columns)} columns")
        
        # Check all column names to identify potential SysAid columns
        log_message("All columns in file:")
        for i, col in enumerate(df.columns):
            log_message(f"  {i+1}. {col}")
        
        # Look for potential SysAid columns based on common naming patterns
        potential_sysaid_cols = [col for col in df.columns if 
                              any(pattern in col.upper() for pattern in 
                                  ['SYSAID', 'TICKET', 'CR', 'SR', 'CHANGE', 'REQUEST'])]
        
        if potential_sysaid_cols:
            log_message(f"\nPotential SysAid columns found: {potential_sysaid_cols}")
            
            # Analyze each potential SysAid column
            for col in potential_sysaid_cols:
                log_message(f"\nAnalyzing column: {col}")
                # Count non-empty values
                non_empty = df[col].dropna()
                log_message(f"  Non-empty values: {len(non_empty)} out of {len(df)} ({len(non_empty)/len(df)*100:.2f}%)")
                
                # Get unique values
                unique_values = df[col].dropna().unique()
                log_message(f"  Unique non-empty values: {len(unique_values)}")
                
                # Show a sample of unique values
                sample_size = min(15, len(unique_values))
                log_message(f"  Sample of unique values (top {sample_size}):")
                for i, val in enumerate(unique_values[:sample_size]):
                    log_message(f"    {i+1}. '{val}'")
                
                # Show value distribution
                value_counts = df[col].value_counts().head(10)
                log_message("  Top value frequencies:")
                for val, count in value_counts.items():
                    log_message(f"    '{val}': {count} rows")
                
                # Check for standardized naming patterns
                has_prefix = False
                for val in unique_values:
                    if isinstance(val, str) and any(prefix in val for prefix in ['#', 'SR-', 'CR-', 'SR', 'CR']):
                        has_prefix = True
                        break
                log_message(f"  Has standard prefixes (like #, SR-, CR-): {has_prefix}")
        else:
            log_message("No obvious SysAid columns found")
            
    except Exception as e:
        log_message(f"Error analyzing file: {str(e)}")

if __name__ == "__main__":
    analyze_source_file(r"input\Mar_SM20_Sys.xlsx")
