import pandas as pd

# Read the audit report
df = pd.read_excel('../OneDrive/Documents/Python/SAP_Audit_Report.xlsx', sheet_name='Session_Timeline')
print(f"Total records: {len(df)}")

# Look for records with vendor-related fields
print("\n=== CHECKING FOR VENDOR-RELATED FIELDS ===")
vendor_records = df[df['risk_factors'].str.contains('vendor', case=False, na=False)]
print(f"Records with 'vendor' in risk_factors: {len(vendor_records)}")
if len(vendor_records) > 0:
    print("\nSample vendor records:")
    sample = vendor_records[['Field', 'Old_Value', 'New_Value', 'risk_factors']].head(3)
    for _, row in sample.iterrows():
        print(f"\nField: {row['Field']}")
        print(f"Value: {row['Old_Value']} -> {row['New_Value']}")
        print(f"Risk Factor: {row['risk_factors']}")

# Check for KRED field
print("\n=== CHECKING FOR KRED FIELD ===")
kred_records = df[df['Field'] == 'KRED']
print(f"Records with KRED field: {len(kred_records)}")

# Check how field descriptions appear in risk factors
print("\n=== FIELD DESCRIPTION SAMPLES ===")
for field in ['KRED', 'LIFNR', 'QUAN', 'LOEVM', 'VLSTK']:
    # Look for instances where these field names appear in risk_factors
    mentions = df[df['risk_factors'].str.contains(f"{field} \(", case=True, regex=True, na=False)]
    print(f"Records mentioning {field} with description: {len(mentions)}")
    if len(mentions) > 0:
        sample = mentions['risk_factors'].iloc[0]
        print(f"  Sample: {sample}")

# Check for all the vendor fields we added
print("\n=== CHECKING FOR ALL VENDOR FIELDS ===")
vendor_fields = ['KRED', 'KREDI', 'KTOKK', 'XCPDK']
for field in vendor_fields:
    direct_field = df[df['Field'] == field]
    print(f"Records with {field} as field: {len(direct_field)}")
    mentions = df[df['risk_factors'].str.contains(field, case=True, na=False)]
    print(f"Records mentioning {field} in risk factors: {len(mentions)}")
