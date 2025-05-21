#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored) - Part 5: Risk Assessment
"""

# --- Risk Assessment and Pattern Detection ---
# Define sensitive tables and transaction codes
def get_sensitive_tables():
    """Return a set of sensitive SAP tables to monitor."""
    return {
        # Security Tables
        "USR01", "USR02", "USR04", "USR10", "USR12", "USR21", "USR40", "UST10C", "UST04",
        "AGR_1251", "AGR_USERS", "AGR_DEFINE", "DEVACCESS", "USER_ADDR", "PROFILE",
        "RSECTAB", "PRGN_CUST", "USOBT", "UST12", "SUSR", "USER_LOG",
        
        # Audit and Monitoring
        "RSAU_PERS", "RSAU_CONFIG", "RSAUFILES", "RSAU_VAL", "RSAUDIT_CASES", "RSAU_CONTROL",
        "RSECACTPRO", "RSECUDATA", "TPCF", "TST01",
        
        # Payment and Banking
        "REGUH", "PAYR", "BSEC", "FPLT", "T042Z", "BSEG", "TIBAN", "T012K", "T012T", "T001B",
        
        # Basis
        "TADIR", "TRDIR", "E071", "E070", "T000", "DDLOG", "TDEVC", "REPOS", "D010TAB",
        "D010INC", "NRIV", "TST01", "TMS_SRCSYS", "RSPARAM", "TSP01", "TPFET", "TPSRV",
        "TPSTAT", "VARI",
        
        # Financial
        "BKPF", "BSEG", "SKA1", "SKB1", "T030", "T001", "T001B", "T009", "T009B",
        "FAGLFLEXA", "FAGLFLEXT", "CSKS", "CSKB", "CEPC", "TKA01", "T003", "T012",
        "T012K", "BNKA", "REGUH", "PAYR", "TCURR", "TCURF", "TCURV", "T043T", "T042Y",
        
        # Jobs
        "TBTCO", "TBTCP", "TSDIR", "TBTCS", "BTCEVTJOB", "BTCJSTAT", "BTCSEVJOB", "BTCSYSPRD",
        
        # Materials Management
        "MCHA", "MCH1", "MSEG", "MKPF", "MBEW", "EKKO", "EKPO", "EINA", "EINE", "T156", "MARM",
        
        # Sales and Distribution
        "VBAK", "VBAP", "LIKP", "LIPS", "VBRK", "VBRP", "KNVV", "KONV", "A004", "A305",
        
        # Master Data
        "KNA1", "KNB1", "LFA1", "LFB1", "MARA", "MARC", "MVKE", "LFBK", "BUT000",
        
        # Workflow
        "SWWWIHEAD", "SWWUSERWI", "SWWCONT", "SWP_STEP", "SWWLOGHIST",
        
        # Cannabis Industry (if applicable)
        "AUSP", "OBJK", "INOB", "KLAH", "KSSK",
        
        # Add any custom Z-tables that are sensitive for your organization
        # "Z_SENSITIVE_TABLE1", "Z_SENSITIVE_TABLE2"
    }

def get_critical_field_patterns():
    """Return patterns for critical fields that should be monitored closely."""
    return {
        # Authentication and authorization fields
        r"(?i)PASS(WORD)?": "Password field",
        r"(?i)AUTH(ORIZATION)?": "Authorization field",
        r"(?i)ROLE": "Role assignment field",
        r"(?i)PERM(ISSION)?": "Permission field",
        r"(?i)ACCESS": "Access control field",
        r"(?i)KEY": "Security key field",
        r"(?i)CRED(ENTIAL)?": "Credential field",
        r"(?i)TOKEN": "Security token field",
        
        # Financial fields
        r"(?i)AMOUNT": "Financial amount field",
        r"(?i)CURR(ENCY)?": "Currency field",
        r"(?i)BANK": "Banking information field",
        r"(?i)ACCOUNT": "Account field",
        r"(?i)PAYMENT": "Payment field",
        r"(?i)CREDIT": "Credit field",
        r"(?i)TAX": "Tax field",
        
        # Master data fields
        r"(?i)VENDOR": "Vendor master data field",
        r"(?i)CUSTOMER": "Customer master data field",
        r"(?i)EMPLOYEE": "Employee data field",
        r"(?i)ADDRESS": "Address field",
        r"(?i)CONTACT": "Contact information field",
        
        # System configuration
        r"(?i)CONFIG": "Configuration field",
        r"(?i)SETTING": "System setting field",
        r"(?i)PARAM(ETER)?": "Parameter field",
        r"(?i)FLAG": "System flag field",
        r"(?i)MODE": "System mode field"
    }

def get_sensitive_tcodes():
    """Return a set of sensitive SAP transaction codes to monitor."""
    return {
        # Debugging
        "RSDEBUG", "/H", "/IWBEP/TRACES", "/IWFND/ERROR_LOG", "ST22", "ST05",
        
        # Audit and Compliance
        "SM19", "SM20", "RSAU_CONFIG", "GRC_RULESET", "GRC_RISK", "RMPS",
        "NWBC_AUDITING", "DPRM", "SARA",
        
        # Payment and Banking
        "F110", "FBPM", "FB70", "FCH5", "FC10", "FF67", "FF_5", "FCHI", "BPAY",
        
        # Table Maintenance
        "SE11", "SE14", "SE16N", "SM30", "SM31", "MASS",
        
        # Code Changes
        "SE38", "SE80", "SE24", "SE37", "SE09", "SE10", "SMOD", "CMOD",
        
        # Configuration
        "SPRO", "RZ10", "RZ11", "SCC4", "SCC5", "SCC7",
        
        # User Management
        "SU01", "SU10", "SU53", "SUIM", "PFCG", "SU25", "SU24", "SU56",
        
        # System Administration
        "SM49", "SM59", "SM69", "SM21", "SM37", "SM50", "SM51", "SM66",
        "RZ03", "RZ04", "RZ12", "RZ70", "STMS", "SPAM", "SAINT",
        
        # Sensitive Business Transactions
        "XK01", "XK02", "FK01", "FK02", "MK01", "MK02", "ME21N", "ME22N",
        "ME23N", "FB60", "FB65", "F-02", "F-01", "FBL1N", "FBL3N", "FBL5N",
        
        # Add any custom Z-transactions that are sensitive for your organization
        # "Z_SENSITIVE_TCODE1", "Z_SENSITIVE_TCODE2"
    }

def assess_risk_legacy(correlated_data, unmatched_cdpos, unmatched_sm20):
    """
    Assess risk in the legacy correlation mode (direct SM20-CDPOS correlation).
    Returns a DataFrame with risk assessments.
    """
    log_message("Assessing risk in legacy correlation mode...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = correlated_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        critical_field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Assess risk based on sensitive tables
        if 'Table_Name' in risk_df.columns:
            risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_level'] = 'High'
            risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] = \
                risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
        
        # Assess risk based on sensitive transaction codes
        # Check both SM20 and CDPOS transaction codes
        if SM20_TCODE_COL in risk_df.columns:
            risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        if 'TCode_CD' in risk_df.columns:
            risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        # Assess risk based on critical field patterns
        if CDPOS_FNAME_COL in risk_df.columns:
            for pattern, description in critical_field_patterns.items():
                mask = risk_df[CDPOS_FNAME_COL].str.contains(pattern, regex=True, na=False)
                risk_df.loc[mask, 'risk_level'] = 'High'
                risk_df.loc[mask, 'risk_factors'] = \
                    risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
            risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
        
        # Assess risk based on change indicator
        if 'Change_Indicator' in risk_df.columns:
            # Insert (I) and Delete (D) operations are higher risk than Update (U)
            risk_df.loc[risk_df['Change_Indicator'].isin(['I', 'D']), 'risk_level'] = 'High'
            risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] = \
                risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] + 'Insert operation; '
            risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] = \
                risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] + 'Delete operation; '
            
            # Updates are medium risk by default
            medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df['Change_Indicator'] == 'U')
            risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
            risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        return correlated_data

def assess_risk_session(session_data):
    """
    Assess risk in the session-based mode.
    Returns a DataFrame with risk assessments.
    """
    log_message("Assessing risk in session-based mode...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        critical_field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Assess risk based on sensitive tables
        if SESSION_TABLE_COL in risk_df.columns:
            risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
        
        # Assess risk based on sensitive transaction codes
        if SESSION_TCODE_COL in risk_df.columns:
            risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        # Assess risk based on critical field patterns
        if SESSION_FIELD_COL in risk_df.columns:
            for pattern, description in critical_field_patterns.items():
                mask = risk_df[SESSION_FIELD_COL].str.contains(pattern, regex=True, na=False)
                risk_df.loc[mask, 'risk_level'] = 'High'
                risk_df.loc[mask, 'risk_factors'] = \
                    risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
            risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
        
        # Assess risk based on change indicator
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) and Delete (D) operations are higher risk than Update (U)
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL].isin(['I', 'D']), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] + 'Insert operation; '
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] + 'Delete operation; '
            
            # Updates are medium risk by default
            medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
            risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
            risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        return session_data
