import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
import sys

# Get the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
import random

# Create sample data for SM20 Security Audit Log
def create_sm20_data(num_records=100):
    # Define users (including some firefighter IDs)
    users = ['ADMIN', 'FF_JOHN', 'FF_MARY', 'SYSTEM', 'FF_TECH1', 'DEVELOPER']
    
    # Define transaction codes
    tcodes = ['SE38', 'SE11', 'SM30', 'PFCG', 'SU01', 'FB01', 'MM01', 'VA01', 'RSDEBUG', 'SM37']
    
    # Define message templates
    msg_templates = [
        "Transaction {} started",
        "Display table {}",
        "Change table {}",
        "User {} logged in",
        "RFC call to function {}",
        "Debug session started",
        "Report {} executed"
    ]
    
    # Define tables
    tables = ['USR01', 'BKPF', 'BSEG', 'MARA', 'KNA1', 'LFA1', 'T001', 'VBAK', 'AGR_USERS']
    
    # Generate random dates within the last month
    base_date = datetime.now() - timedelta(days=30)
    dates = [base_date + timedelta(minutes=random.randint(0, 43200)) for _ in range(num_records)]
    dates.sort()  # Sort dates chronologically
    
    # Create dataframe
    data = {
        'Date': [d.strftime('%m/%d/%Y') for d in dates],
        'Time': [d.strftime('%H:%M:%S') for d in dates],
        'User': [random.choice(users) for _ in range(num_records)],
        'TA': [random.choice(tcodes) for _ in range(num_records)],
        'Terminal': [f'TERM{random.randint(1, 10)}' for _ in range(num_records)],
        'Client': [f'{random.randint(100, 999)}' for _ in range(num_records)]
    }
    
    # Generate messages
    messages = []
    for i in range(num_records):
        template = random.choice(msg_templates)
        if 'table' in template:
            messages.append(template.format(random.choice(tables)))
        elif 'Transaction' in template:
            messages.append(template.format(data['TA'][i]))
        elif 'User' in template:
            messages.append(template.format(data['User'][i]))
        elif 'function' in template:
            messages.append(template.format(f'Z_FUNC_{random.randint(1000, 9999)}'))
        elif 'Report' in template:
            messages.append(template.format(f'Z_REPORT_{random.randint(1000, 9999)}'))
        else:
            messages.append(template)
    
    data['Audit Log Msg . Text'] = messages
    
    return pd.DataFrame(data)

# Create sample data for CDHDR Change Document Header
def create_cdhdr_data(num_records=150):
    # Define users (including some firefighter IDs)
    users = ['ADMIN', 'FF_JOHN', 'FF_MARY', 'SYSTEM', 'FF_TECH1', 'DEVELOPER']
    
    # Define transaction codes
    tcodes = ['SE38', 'SE11', 'SM30', 'PFCG', 'SU01', 'FB01', 'MM01', 'VA01', 'RSDEBUG', 'SM37']
    
    # Define object classes
    object_classes = ['MATERIAL', 'CUSTOMER', 'VENDOR', 'USER', 'ROLE', 'DOCUMENT', 'COMPANY']
    
    # Generate random dates within the last month
    base_date = datetime.now() - timedelta(days=30)
    dates = [base_date + timedelta(minutes=random.randint(0, 43200)) for _ in range(num_records)]
    dates.sort()  # Sort dates chronologically
    
    # Create dataframe
    data = {
        'Date': [d.strftime('%m/%d/%Y') for d in dates],
        'Time': [d.strftime('%H:%M:%S') for d in dates],
        'User': [random.choice(users) for _ in range(num_records)],
        'TCode': [random.choice(tcodes) for _ in range(num_records)],
        'Doc . Num': [f'CD{str(i+1000).zfill(8)}' for i in range(num_records)],
        'Object Class': [random.choice(object_classes) for _ in range(num_records)],
        'Object Value': [f'OBJ{random.randint(10000, 99999)}' for _ in range(num_records)]
    }
    
    return pd.DataFrame(data)

# Create sample data for CDPOS Change Document Items
def create_cdpos_data(cdhdr_df):
    # Get change document numbers from CDHDR
    change_docs = cdhdr_df['Doc . Num'].tolist()
    
    # Define tables
    tables = ['USR01', 'BKPF', 'BSEG', 'MARA', 'KNA1', 'LFA1', 'T001', 'VBAK', 'AGR_USERS']
    
    # Define change indicators
    change_indicators = ['U', 'I', 'D', 'E']
    
    # Define fields
    fields = {
        'USR01': ['BNAME', 'CLASS', 'USTYP', 'GLTGV', 'GLTGB'],
        'BKPF': ['BUKRS', 'BELNR', 'GJAHR', 'BLART', 'BLDAT'],
        'MARA': ['MATNR', 'MTART', 'MATKL', 'MEINS', 'MSTAE'],
        'KNA1': ['KUNNR', 'NAME1', 'LAND1', 'ORT01', 'STRAS'],
        'AGR_USERS': ['AGR_NAME', 'UNAME', 'FROM_DAT', 'TO_DAT', 'MODIFIED']
    }
    
    # Generate multiple items per change document
    data = []
    for doc_num in change_docs:
        # Generate 1-5 items per document
        num_items = random.randint(1, 5)
        table = random.choice(tables)
        
        for _ in range(num_items):
            # Select field based on table
            if table in fields:
                field = random.choice(fields[table])
            else:
                field = f'FIELD{random.randint(1, 10)}'
            
            item = {
                'Doc . Num': doc_num,
                'Table Name': table,
                'Change Type': random.choice(change_indicators),
                'Field Name': field,
                'New Value': f'NEW_{random.randint(1000, 9999)}',
                'Old Value': f'OLD_{random.randint(1000, 9999)}'
            }
            data.append(item)
    
    return pd.DataFrame(data)

# Generate the sample data
print("Generating sample data...")
sm20_df = create_sm20_data(100)
cdhdr_df = create_cdhdr_data(150)
cdpos_df = create_cdpos_data(cdhdr_df)

# Save to Excel files
print("Saving to Excel files...")
# Create input directory if it doesn't exist
input_dir = os.path.join(SCRIPT_DIR, 'input')
os.makedirs(input_dir, exist_ok=True)

# Use absolute paths
sm20_df.to_excel(os.path.join(input_dir, 'feb_sm20_FF.xlsx'), index=False)
cdhdr_df.to_excel(os.path.join(input_dir, 'feb_CDHDR_FF.xlsx'), index=False)
cdpos_df.to_excel(os.path.join(input_dir, 'feb_CDPOS_FF.xlsx'), index=False)

print("Sample data created successfully!")