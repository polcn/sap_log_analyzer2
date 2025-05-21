import pandas as pd
import os as os

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")

# Input files (standardized names from data prep script)
SM20_FILE = os.path.join(INPUT_DIR, "SM20.csv")
CDHDR_FILE = os.path.join(INPUT_DIR, "CDHDR.csv")
CDPOS_FILE = os.path.join(INPUT_DIR, "CDPOS.csv")

# Load the cleaned SAP audit logs
cdhdr = pd.read_csv(CDHDR_FILE, usecols=[
    "OBJECT", "OBJECT VALUE", "DOC.NUMBER", "USER", "DATE", "TIME", "TCODE", "CHANGE FLAG FOR APPLICATION OBJECT"
])
cdpos = pd.read_csv(CDPOS_FILE, usecols=[
    "OBJECT", "OBJECT VALUE", "DOC.NUMBER", "TABLE NAME", "TABLE KEY", "FIELD NAME",
    "CHANGE INDICATOR", "TEXT FLAG", "NEW VALUE", "OLD VALUE"
])
sm20 = pd.read_csv(SM20_FILE, usecols=[
    "DATE", "TIME", "EVENT", "USER", "SOURCE TA", "ABAP SOURCE", "AUDIT LOG MSG. TEXT", "NOTE"
])

# Example preview
print("CDHDR sample:")
print(cdhdr.head())

print("\nCDPOS sample:")
print(cdpos.head())

print("\nSM20 sample:")
print(sm20.head())

