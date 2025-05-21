
#!/usr/bin/env python3

import pandas as pd
import re
from datetime import datetime

# --- Configuration ---

sensitive_tables = {
    "USR01", "AGR_USERS", "BSEG", "T012K", "REGUH", "MCHA", "MCH1", "MSEG", "MKPF", "MBEW"
}

sensitive_tcodes = {
    "RSDEBUG", "/H", "ST22", "SU01", "SU10", "PFCG", "SE11", "SE16N", "SM30", 
    "SE38", "SE80", "SE24", "F110", "FBPM", "FB70", "ME21N", "ME22N"
}

critical_fields = {
    r"(?i)PASS(WORD)?": "Password field",
    r"(?i)AUTH(ORIZATION)?": "Authorization field",
    r"(?i)ROLE": "Role assignment field",
    r"(?i)AMOUNT": "Financial amount field",
    r"(?i)CURRENCY": "Currency field",
    r"(?i)BANK": "Banking information field",
    r"(?i)VENDOR": "Vendor master data field",
    r"(?i)CUSTOMER": "Customer master data field",
    r"(?i)POTENCY": "Potency field (inventory)"
}

# --- Risk Assessment Function ---

def firefighter_risk_assessment(row):
    risk_level = 'Low'
    risk_factors = []

    # Sensitive table and operation type checks
    if row.get('Table') in sensitive_tables:
        if row.get('Change_Indicator') in ['I', 'D']:
            risk_level = 'High'
            risk_factors.append(f"{'Insert' if row['Change_Indicator']=='I' else 'Delete'} operation on sensitive table")
        elif row.get('Change_Indicator') == 'U':
            if risk_level != 'High':
                risk_level = 'Medium'
                risk_factors.append("Update operation on sensitive table")

    # Sensitive Transaction Codes
    if row.get('TCode') in sensitive_tcodes:
        risk_level = 'High'
        risk_factors.append('Sensitive transaction code executed')

    # Critical Field Changes
    field_name = row.get('Field', '')
    for pattern, desc in critical_fields.items():
        if re.search(pattern, field_name, re.IGNORECASE):
            risk_level = 'High'
            risk_factors.append(f"Change to critical field: {desc}")
            break

    # Display Transactions Resulting in Changes
    if row.get('display_but_changed', False):
        risk_level = 'High'
        risk_factors.append('Display transaction resulted in changes')

    row['risk_level'] = risk_level
    row['risk_factors'] = '; '.join(risk_factors) if risk_factors else 'Routine privileged activity'

    return row

# --- Main Function for Testing ---

def main(input_csv, output_csv):
    df = pd.read_csv(input_csv)
    df = df.apply(firefighter_risk_assessment, axis=1)
    df.to_csv(output_csv, index=False)
    print(f"Risk assessment complete. Output saved to {output_csv}")

# --- Script Execution Entry Point ---

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python firefighter_risk_assessment.py <input_csv> <output_csv>")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_csv = sys.argv[2]
    
    main(input_csv, output_csv)
