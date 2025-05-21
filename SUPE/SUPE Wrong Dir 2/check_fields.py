import pandas as pd
import os

# Path to SM20 file
sm20_file = os.path.join(os.environ['USERPROFILE'], "OneDrive", "Documents", "Python", "input", "feb_sm20_FF.xlsx")

# Read the file
print(f"Reading {sm20_file}...")
try:
    df = pd.read_excel(sm20_file)
    print(f"Successfully read Excel file with {len(df)} rows")
    
    # Display column names
    print("\nColumn names:")
    for i, col in enumerate(df.columns):
        print(f"{i}: {col}")
    
    # Check for variable fields
    var_fields = ['First Variable Value for Event', 'Variable 2', 'Variable Data for Message']
    for field in var_fields:
        field_exists = field in df.columns
        print(f"\nField '{field}' exists: {field_exists}")
        if field_exists:
            # Show a sample of values
            non_null_count = df[field].count()
            print(f"  Non-null values: {non_null_count}")
            print(f"  Sample values: {df[field].dropna().head(3).tolist()}")
    
except Exception as e:
    print(f"Error: {str(e)}")
