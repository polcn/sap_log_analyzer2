#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions

This module contains the risk assessment functions for the SAP Audit Tool.
"""

import os
import re
from datetime import datetime
import pandas as pd

# --- Column Name Mapping (UPPERCASE) ---
# SM20 Security Audit Log columns
SM20_TCODE_COL = 'SOURCE TA'
CDPOS_FNAME_COL = 'FIELD NAME'

# Session Timeline columns (from SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'

# Risk assessment configuration
HIGH_RISK_COLOR = '#FFC7CE'
MEDIUM_RISK_COLOR = '#FFEB9C'
LOW_RISK_COLOR = '#C6EFCE'

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

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
        
        # Additional security tables
        "TSTC", "TSTCA", "TSTCT", "TSTCP", "TSTCC",  # Transaction code tables
        "TOBJ", "TOBJT", "TACT", "TACTZ", "TACTT",   # Authorization object tables
        
        # Transport system additional tables
        "TRBAT", "TRJOB",
        
        # Client administration additional tables
        "TCLT", "TMSCSYS",
        
        # System configuration additional tables
        "TPARA", "TPARAT", "TPARAMV", "TZPARS",
        
        # Additional financial tables
        "ACCT", "ACCTHD", "ACDOCA", "BSAD", "BSAK", "BSID", "BSIK"
    }

def get_sensitive_table_descriptions():
    """Return detailed descriptions for sensitive SAP tables."""
    return {
        # Security Tables
        "USR01": "User master record maintenance - Core user data changes",
        "USR02": "User password management - Credential changes",
        "USR04": "User authorization data - User security profiles", 
        "USR10": "User parameters - User customization settings",
        "USR12": "User master record history - Historical user data changes",
        "USR21": "User address data - User contact information",
        "USR40": "User group assignments - User organizational data",
        "AGR_1251": "Role permissions - Authorization object assignments",
        "AGR_USERS": "Role assignments - Security authorization assignments to users",
        "AGR_DEFINE": "Role definitions - Security role structure definitions",
        "DEVACCESS": "Development access control - Developer permissions changes",
        "USER_ADDR": "User address information - Contact details changes",
        "PROFILE": "Security profiles - Authorization configurations",
        
        # Basis Tables
        "TADIR": "Repository object directory - Development system object definitions",
        "TRDIR": "Program directory - ABAP program metadata changes",
        "E071": "Transport request objects - Change management items",
        "E070": "Transport request header - Change request metadata",
        "T000": "Client administration - System client configuration changes",
        "TDEVC": "Development class - Package assignment changes",
        
        # Financial Tables
        "BKPF": "Accounting document header - Financial document changes",
        "BSEG": "Accounting document segment - Financial posting data modification",
        "FAGLFLEXA": "General ledger line items - Financial transaction data",
        "FAGLFLEXT": "General ledger totals - Financial balances and totals",
        
        # Transaction code tables
        "TSTC": "Transaction code registry - Transaction definition changes",
        "TSTCA": "Transaction code assignments - Transaction linking changes",
        "TSTCT": "Transaction code text - Transaction descriptions",
        
        # Authorization tables
        "TOBJ": "Authorization objects - Security permission objects",
        "TOBJT": "Authorization object texts - Security permission descriptions",
        "TACT": "Activity definitions - Action permissions configuration"
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

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns."""
    return {
        # Authentication and authorization fields
        r"(?i)PASS(WORD)?": "Password/credential modification - Security sensitive change that affects user authentication",
        r"(?i)AUTH(ORIZATION)?": "Authorization configuration - Security permission change that affects access control",
        r"(?i)ROLE": "Role configuration - Security access control change that may modify user permissions",
        r"(?i)PERM(ISSION)?": "Permission settings - Access control modification that affects security boundaries",
        r"(?i)ACCESS": "Access control field - Controls system or resource availability to users",
        r"(?i)KEY": "Security key/token - Security infrastructure change affecting encryption or authentication",
        r"(?i)CRED(ENTIAL)?": "Credential field - Authentication data that may grant system access",
        r"(?i)TOKEN": "Security token field - Authentication or session management critical data",
        
        # Financial fields
        r"(?i)AMOUNT": "Financial amount field - Monetary value change that affects financial transactions",
        r"(?i)CURR(ENCY)?": "Currency field - Financial data type affecting monetary calculations",
        r"(?i)BANK": "Banking details - Payment routing information change affecting financial transactions",
        r"(?i)ACCOUNT": "Account field - Financial or user account record changes",
        r"(?i)PAYMENT": "Payment field - Financial transaction data affecting money movement",
        r"(?i)CREDIT": "Credit field - Financial credit information affecting balance calculations",
        r"(?i)TAX": "Tax field - Financial tax calculation data affecting financial reporting",
        
        # Master data fields
        r"(?i)VENDOR": "Vendor master data field - Supplier information affecting procurement processes",
        r"(?i)CUSTOMER": "Customer master data field - Client information affecting sales and billing",
        r"(?i)EMPLOYEE": "Employee data field - Personnel information affecting HR processes",
        r"(?i)ADDRESS": "Address field - Location information for entities in the system",
        r"(?i)CONTACT": "Contact information field - Communication details for entities in the system",
        
        # System configuration
        r"(?i)CONFIG": "Configuration field - System setting that affects overall behavior",
        r"(?i)SETTING": "System setting field - Parameter that controls system functionality",
        r"(?i)PARAM(ETER)?": "Parameter field - System configuration option that affects behavior",
        r"(?i)FLAG": "System flag field - Boolean setting that enables/disables features",
        r"(?i)MODE": "System mode field - Setting that changes system operating characteristics"
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
        
        # Additional security transactions
        "SCC4", "SCC1", "SCC2", "SCC3",  # Client administration
        "SCUG", "SCUG_COMPARE",          # Cross-client user group maintenance
        "SU22", "SU24", "SU25",          # Security authorization tools
        "SUPC", "SUIM", "S_BCE_68001403", # Security reporting and administration
        
        # Additional development transactions
        "SE01", "SE03", "SE41", "SE51", "SE61", "SE71", "SE81", "SE91",
        "SE18", "SEOS", "SFES",
        
        # System monitoring and administration
        "DB02", "DB20", "DB13", "DB50",  # Database administration
        "SM01", "SM02", "SM04", "SM12", "SM13"  # System locks and updates
    }

def get_sensitive_tcode_descriptions():
    """Return detailed descriptions for sensitive SAP transaction codes."""
    return {
        # User Management
        "SU01": "User maintenance - Account creation or modification",
        "SU10": "Mass user maintenance - Bulk user account changes",
        "PFCG": "Role maintenance - Security authorization changes",
        "SU24": "Authorization defaults - Security object assignment maintenance",
        "SUIM": "User information system - Security reporting and analysis",
        "SU53": "Authorization check tool - Security troubleshooting access",
        "SU56": "User comparison - Security profiles comparison",
        
        # Development
        "SE38": "ABAP Editor - Custom code development and modification",
        "SE80": "Object Navigator - Development environment access for code changes",
        "SE24": "Class Builder - Object-oriented development",
        "SE37": "Function Builder - Function module development",
        "SE09": "Transport Organizer - Change management organization",
        "SE10": "Transport Organizer tools - Release management for changes",
        "SMOD": "Enhancements - Standard code modification points",
        "CMOD": "Project management for modifications - Coordinates SAP changes",
        
        # Table Maintenance
        "SE11": "Data Dictionary maintenance - Table structure modifications",
        "SE14": "Database utility - Database table adjustments",
        "SE16N": "Table data browser - Direct table content access",
        "SM30": "Table maintenance - Direct data modification",
        "SM31": "Table maintenance generator - Data maintenance configuration",
        
        # System Administration
        "SM49": "External OS commands - Server operating system access",
        "SM59": "RFC destinations - Remote connection management",
        "SM69": "External commands maintenance - Operating system command configuration",
        "SM37": "Background job overview - Background processing management",
        "SM50": "Process overview - Application server administration",
        "SM51": "System overview - SAP system landscape administration",
        "STMS": "Transport Management System - Moving changes between environments",
        
        # Debugging
        "RSDEBUG": "ABAP Debugger - Code execution debugging",
        "/H": "Direct system debugging - Run-time code exploration",
        "ST22": "ABAP dump analysis - System crash investigation",
        
        # Configuration
        "SPRO": "Customizing - Implementation guide for system configuration",
        "RZ10": "Profile parameters - System configuration management",
        "RZ11": "Profile parameter maintenance - System configuration details",
        
        # Financial
        "F110": "Payment run - Automated payment execution",
        "FB60": "Enter incoming invoices - Vendor invoice processing",
        "FB65": "Enter outgoing invoices - Customer invoice processing",
        "F-01": "General document entry - Manual financial posting",
        "F-02": "General document change - Financial document modification"
    }

def classify_activity_type(row):
    """Classify the type of support activity being performed."""
    # Development activities
    if row[SESSION_TCODE_COL] in {'SE38', 'SE80', 'SE09', 'SE10', 'SE24', 'SE37'}:
        return "Development activity"
    
    # Security administration
    if row[SESSION_TCODE_COL] in {'SU01', 'SU10', 'PFCG', 'SU24', 'SUIM'}:
        return "Security administration"
    
    # System configuration
    if row[SESSION_TCODE_COL] in {'RZ10', 'RZ11', 'SM30', 'SM31', 'SPRO'}:
        return "System configuration"
    
    # Data maintenance
    if row[SESSION_TCODE_COL] in {'SE16', 'SE16N', 'SM30', 'SM31', 'SM35'}:
        if SESSION_CHANGE_IND_COL in row and row[SESSION_CHANGE_IND_COL] in {'U', 'I', 'D'}:
            return "Direct data modification"
        return "Data access"
    
    # Transport management
    if row[SESSION_TCODE_COL] in {'STMS', 'SE09', 'SE10'}:
        return "Transport management"
    
    # Background processing
    if row[SESSION_TCODE_COL] in {'SM37', 'SM36', 'SM50'}:
        return "Background processing administration"
    
    # Default
    return "General system administration"

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
    Assess risk in the session-based mode with enhanced descriptions.
    Returns a DataFrame with risk assessments.
    """
    log_message("Assessing risk in session-based mode with enhanced descriptions...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        
        # Get enhanced descriptions
        table_descriptions = get_sensitive_table_descriptions()
        tcode_descriptions = get_sensitive_tcode_descriptions()
        field_descriptions = get_critical_field_pattern_descriptions()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Add activity type classification
        risk_df['activity_type'] = risk_df.apply(classify_activity_type, axis=1)
        
        # Assess risk based on sensitive tables with enhanced descriptions
        if SESSION_TABLE_COL in risk_df.columns:
            tables_mask = risk_df[SESSION_TABLE_COL].isin(sensitive_tables)
            risk_df.loc[tables_mask, 'risk_level'] = 'High'
            
            # Apply detailed descriptions for each table
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL] == table
                if any(table_mask):
                    # Use enhanced description if available, else use generic
                    description = table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    risk_df.loc[table_mask, 'risk_factors'] = description
        
        # Assess risk based on sensitive transaction codes with enhanced descriptions
        if SESSION_TCODE_COL in risk_df.columns:
            tcodes_mask = risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes)
            risk_df.loc[tcodes_mask, 'risk_level'] = 'High'
            
            # Apply detailed descriptions for each tcode
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL] == tcode
                if any(tcode_mask):
                    # Use enhanced description if available, else use generic
                    description = tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    risk_df.loc[tcode_mask, 'risk_factors'] = description
        
        # Assess risk based on critical field patterns with enhanced descriptions
        if SESSION_FIELD_COL in risk_df.columns:
            for pattern, basic_desc in get_critical_field_patterns().items():
                mask = risk_df[SESSION_FIELD_COL].str.contains(pattern, regex=True, na=False)
                if any(mask):
                    risk_df.loc[mask, 'risk_level'] = 'High'
                    # Use enhanced description if available, else use the basic one
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    risk_df.loc[mask, 'risk_factors'] = description
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            mask = risk_df['display_but_changed']
            risk_df.loc[mask, 'risk_level'] = 'High'
            risk_df.loc[mask, 'risk_factors'] = \
                "Display transaction with changes - Activity logged as view-only but includes data modifications"
        
        # Assess risk based on change indicator
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL] == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                # Provide context about which table is being modified
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[insert_mask, 'risk_factors'] = risk_df.loc[insert_mask].apply(
                        lambda x: f"Insert operation - New record created in {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[insert_mask, 'risk_factors'] = "Insert operation - New record created"
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL] == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                # Provide context about which table is being modified
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[delete_mask, 'risk_factors'] = risk_df.loc[delete_mask].apply(
                        lambda x: f"Delete operation - Record removed from {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[delete_mask, 'risk_factors'] = "Delete operation - Record removed"
            
            # Updates (U) are medium risk by default if not already high risk
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                # Provide context about which table is being modified
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[update_mask, 'risk_factors'] = risk_df.loc[update_mask].apply(
                        lambda x: f"Update operation - Existing record modified in {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[update_mask, 'risk_factors'] = "Update operation - Existing record modified"
        
        # Medium risk classification for specific transaction + table combinations
        if SESSION_TCODE_COL in risk_df.columns and SESSION_TABLE_COL in risk_df.columns:
            # Data browser on non-sensitive tables
            browser_mask = (risk_df[SESSION_TCODE_COL] == 'SE16N') & (~risk_df[SESSION_TABLE_COL].isin(sensitive_tables)) & (risk_df['risk_level'] == '
