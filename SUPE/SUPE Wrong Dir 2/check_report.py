import pandas as pd
import sys

# File to check
file_path = r"C:\Users\craig\OneDrive\Documents\Python\SAP_Audit_Report.xlsx"

# Read the Excel file
print(f"Reading file: {file_path}")
df = pd.read_excel(file_path, sheet_name='Session_Timeline')
print(f"Total rows: {len(df)}")

# Print the first few rows showing chronological ordering
print("\nFirst 10 rows:")
for i in range(min(10, len(df))):
    print(f"Session: {df.iloc[i]['Session ID with Date']}, Time: {df.iloc[i]['Datetime']}, Risk: {df.iloc[i]['risk_level']}")

# Show session distribution
print("\nFirst few session groups:")
session_counts = df['Session ID with Date'].value_counts().sort_index().head(10)
print(session_counts)

# Examine risk factors for low-risk items
low_risk_items = df[df['risk_level'] == 'Low']
print(f"\nLow risk items with factors: {len(low_risk_items[low_risk_items['risk_factors'] != ''])}")
print(f"Low risk items without factors: {len(low_risk_items[low_risk_items['risk_factors'] == ''])}")

# Show the most common risk factors for each risk level
print("\nMost common low-risk factors:")
low_risk_factor_counts = low_risk_items['risk_factors'].value_counts().head(3)
print(low_risk_factor_counts)

print("\nMost common medium-risk factors:")
medium_risk_items = df[df['risk_level'] == 'Medium']
medium_risk_factor_counts = medium_risk_items['risk_factors'].value_counts().head(3)
print(medium_risk_factor_counts)

print("\nMost common high-risk factors:")
high_risk_items = df[df['risk_level'] == 'High']
high_risk_factor_counts = high_risk_items['risk_factors'].value_counts().head(3)
print(high_risk_factor_counts)

# Show sample items from each risk level with their factors
print("\nSample low-risk items with factors:")
sample_low_risk = low_risk_items[low_risk_items['risk_factors'] != ''].head(2)
for i, row in sample_low_risk.iterrows():
    print(f"Session: {row['Session ID with Date']}, Risk: {row['risk_level']}, Factor: {row['risk_factors']}")

print("\nSample medium-risk items with factors:")
sample_medium_risk = medium_risk_items[medium_risk_items['risk_factors'] != ''].head(2)
for i, row in sample_medium_risk.iterrows():
    print(f"Session: {row['Session ID with Date']}, Risk: {row['risk_level']}, Factor: {row['risk_factors']}")

print("\nSample high-risk items with factors:")
sample_high_risk = high_risk_items[high_risk_items['risk_factors'] != ''].head(2)
for i, row in sample_high_risk.iterrows():
    print(f"Session: {row['Session ID with Date']}, Risk: {row['risk_level']}, Factor: {row['risk_factors']}")

# Check if sorting is correct by comparing rows
prev_session = None
prev_time = None
correct_order = True
mixed_order = 0

for i in range(len(df)):
    current_session = df.iloc[i]['Session ID with Date']
    current_time = df.iloc[i]['Datetime']
    
    if prev_session is not None and prev_time is not None:
        # If we're still in the same session, times should be ascending
        if current_session == prev_session and current_time < prev_time:
            correct_order = False
            mixed_order += 1
        # If we're in a new session, it should have a higher session number
        elif current_session < prev_session:
            correct_order = False
            mixed_order += 1
    
    prev_session = current_session
    prev_time = current_time

print(f"\nIs ordering correct? {correct_order}")
if not correct_order:
    print(f"Found {mixed_order} instances of incorrect ordering")
