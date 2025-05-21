#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Risk Assessment Functions

This module contains improved risk assessment functions with detailed descriptions
for the SAP Audit Tool.
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
SESSION_USER_COL = 'User'
SESSION_DATETIME_COL = 'Datetime'

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
        "USR01": "User master record maintenance - Core user account information that affects authentication and access",
        "USR02": "User password management - Stores encrypted password hash data and credential settings",
        "USR04": "User authorization data - User security profiles for system access control", 
        "USR10": "User parameters - User customization settings that can affect behavior",
        "AGR_1251": "Role permissions - Authorization object assignments defining security boundaries",
        "AGR_USERS": "Role assignments - Security authorization assignments to user accounts",
        "AGR_DEFINE": "Role definitions - Security role structure definitions",
        "DEVACCESS": "Development access control - Developer permissions affecting system code",
        "USER_ADDR": "User address information - Contact details and location data",
        
        # Basis Tables
        "TADIR": "Repository object directory - Development system object references and definitions",
        "TRDIR": "Program directory - ABAP program metadata including execution control",
        "E071": "Transport request objects - Change management components being moved",
        "E070": "Transport request header - Change request metadata for system changes",
        "T000": "Client administration - System client configuration affecting system separation",
        "TDEVC": "Development class - Package assignment controlling code organization",
        
        # Financial Tables
        "BKPF": "Accounting document header - Financial document control data",
        "BSEG": "Accounting document segment - Financial posting line items with monetary values",
        "FAGLFLEXA": "General ledger line items - Financial transaction data with account assignments",
        "FAGLFLEXT": "General ledger totals - Financial balances and totals by period",
        
        # Transaction code tables
        "TSTC": "Transaction code registry - Transaction definition and execution control",
        "TSTCA": "Transaction code assignments - Links between transactions and programs",
        "TSTCT": "Transaction code text - Transaction descriptions and menu entries",
        
        # Authorization tables
        "TOBJ": "Authorization objects - Security permission objects defining access checks",
        "TOBJT": "Authorization object texts - Security permission descriptions for objects",
        "TACT": "Activity definitions - Action permissions configuration controlling operations"
    }

def get_sensitive_tcodes():
    """Return a set of sensitive SAP transaction codes to monitor."""
    return {
        # Debugging
        "RSDEBUG", "/H", "/IWBEP/TRACES", "/IWFND/ERROR_LOG", "ST22", "ST05",
        
        # Audit and Compliance
        "SM19", "SM20", "RSAU_CONFIG", "GRC_RULESET", "GRC_RISK", "RMPS",
        
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
        "STMS", "SPAM", "SAINT",
        
        # Sensitive Business Transactions
        "XK01", "XK02", "FK01", "FK02", "F-02", "F-01",
        
        # Additional security transactions
        "SCC4", "SCC1", "SCC2", "SCC3",  # Client administration
        "SU22", "SU24", "SU25",           # Security authorization tools
        
        # System monitoring and administration
        "DB02", "DB20", "DB13", "DB50",   # Database administration
        "SM01", "SM02", "SM04", "SM12"    # System locks and updates
    }

def get_sensitive_tcode_descriptions():
    """Return detailed descriptions for sensitive SAP transaction codes."""
    return {
        # User Management
        "SU01": "User maintenance - Creation, modification, and deletion of user accounts affecting security",
        "SU10": "Mass user maintenance - Bulk changes to multiple user accounts simultaneously",
        "PFCG": "Role maintenance - Security authorization profile management and assignment",
        "SU24": "Authorization defaults - Security object assignment maintenance for transactions",
        "SUIM": "User information system - Security reporting and detailed authorization analysis",
        
        # Development
        "SE38": "ABAP Editor - Development of custom code and modification of existing programs",
        "SE80": "Object Navigator - Development environment access for system modifications",
        "SE24": "Class Builder - Object-oriented development of business logic components",
        "SE37": "Function Builder - Function module development and modification",
        "SE09": "Transport Organizer - Change management organization for releasing changes",
        
        # Table Maintenance
        "SE11": "Data Dictionary maintenance - Table structure modifications affecting data schema",
        "SE14": "Database utility - Direct database table adjustments bypassing standard tools",
        "SE16N": "Table data browser - Direct table content access without business validation",
        "SM30": "Table maintenance - Direct data modification bypassing application logic",
        
        # System Administration
        "SM49": "External OS commands - Server operating system access with privileged permissions",
        "SM59": "RFC destinations - Remote connection management for system communication",
        "SM37": "Background job overview - Background processing management and scheduling",
        "SM50": "Process overview - Application server administration and process control",
        "STMS": "Transport Management System - Moving changes between environments (Dev/QA/Prod)",
        
        # Debugging
        "RSDEBUG": "ABAP Debugger - Code execution debugging and inspection at runtime",
        "/H": "Direct system debugging - Low-level code exploration bypassing controls",
        "ST22": "ABAP dump analysis - System crash investigation and technical troubleshooting",
        
        # Configuration
        "SPRO": "Customizing - Implementation guide for comprehensive system configuration",
        "RZ10": "Profile parameters - System-wide configuration management affecting behavior",
        "RZ11": "Profile parameter maintenance - Detailed system configuration parameters",
        
        # Financial
        "F110": "Payment run - Automated payment processing affecting financial transactions",
        "FB60": "Enter incoming invoices - Vendor invoice processing with financial impact",
        "F-01": "General document entry - Manual financial posting to ledger accounts"
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
        
        # Financial fields
        r"(?i)AMOUNT": "Financial amount field",
        r"(?i)CURR(ENCY)?": "Currency field",
        r"(?i)BANK": "Banking information field",
        r"(?i)ACCOUNT": "Account field",
        r"(?i)PAYMENT": "Payment field",
        
        # Master data fields
        r"(?i)VENDOR": "Vendor master data field",
        r"(?i)CUSTOMER": "Customer master data field",
        r"(?i)EMPLOYEE": "Employee data field",
        
        # System configuration
        r"(?i)CONFIG": "Configuration field",
        r"(?i)SETTING": "System setting field",
        r"(?i)PARAM(ETER)?": "Parameter field"
    }

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns."""
    return {
        # Authentication and authorization fields
        r"(?i)PASS(WORD)?": "Password/credential modification - Security sensitive change affecting user authentication",
        r"(?i)AUTH(ORIZATION)?": "Authorization configuration - Security permission change affecting system access control",
        r"(?i)ROLE": "Role configuration - Security access control change affecting user permissions scope",
        r"(?i)PERM(ISSION)?": "Permission settings - Access control modification affecting security boundaries",
        r"(?i)ACCESS": "Access control field - Field controlling system or resource availability",
        r"(?i)KEY": "Security key/token - Infrastructure change affecting encryption or authentication",
        r"(?i)CRED(ENTIAL)?": "Credential field - Authentication data that may grant system access",
        
        # Financial fields
        r"(?i)AMOUNT": "Financial amount field - Monetary value change affecting financial transactions",
        r"(?i)CURR(ENCY)?": "Currency field - Financial data type affecting monetary calculations",
        r"(?i)BANK": "Banking details - Payment routing information change affecting transactions",
        r"(?i)ACCOUNT": "Account field - Financial or user account record modification",
        r"(?i)PAYMENT": "Payment field - Financial transaction data affecting money movement",
        
        # Master data fields
        r"(?i)VENDOR": "Vendor master data field - Supplier information affecting procurement processes",
        r"(?i)CUSTOMER": "Customer master data field - Client information affecting sales processes",
        r"(?i)EMPLOYEE": "Employee data field - Personnel information affecting HR processes",
        
        # System configuration
        r"(?i)CONFIG": "Configuration field - System setting affecting overall system behavior",
        r"(?i)SETTING": "System setting field - Parameter controlling system functionality",
        r"(?i)PARAM(ETER)?": "Parameter field - System configuration option affecting behavior"
    }

def classify_activity_type(row):
    """Classify the type of support activity being performed."""
    try:
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
    except:
        return "Unknown activity type"

def assess_risk_session_enhanced(session_data):
    """
    Enhanced risk assessment function with more detailed descriptions.
    Returns a DataFrame with comprehensive risk assessments.
    """
    log_message("Assessing risk with enhanced descriptions...")
    
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
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL] == table
                if any(table_mask):
                    risk_df.loc[table_mask, 'risk_level'] = 'High'
                    # Use enhanced description if available, else use generic
                    description = table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    risk_df.loc[table_mask, 'risk_factors'] = description
        
        # Assess risk based on sensitive transaction codes with enhanced descriptions
        if SESSION_TCODE_COL in risk_df.columns:
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL] == tcode
                if any(tcode_mask):
                    risk_df.loc[tcode_mask, 'risk_level'] = 'High'
                    # Use enhanced description if available, else use generic
                    description = tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    # Only update risk factors if not already set by table assessment
                    empty_factors_mask = tcode_mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = description
        
        # Assess risk based on critical field patterns with enhanced descriptions
        if SESSION_FIELD_COL in risk_df.columns:
            for pattern, basic_desc in get_critical_field_patterns().items():
                mask = risk_df[SESSION_FIELD_COL].str.contains(pattern, regex=True, na=False)
                if any(mask):
                    risk_df.loc[mask, 'risk_level'] = 'High'
                    # Use enhanced description if available, else use the basic one
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    # Only update risk factors if not already set by table/tcode assessment
                    empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = description
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            mask = risk_df['display_but_changed']
            if any(mask):
                risk_df.loc[mask, 'risk_level'] = 'High'
                # Only update risk factors if not already set by previous assessments
                empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                risk_df.loc[empty_factors_mask, 'risk_factors'] = "Display transaction with changes - Activity logged as view-only but includes data modifications"
        
        # Assess risk based on change indicator - only update if risk factors not already set
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL] == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                # Provide context about which table is being modified
                empty_factors_mask = insert_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation - New record created in {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Insert operation - New record created"
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL] == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                # Provide context about which table is being modified
                empty_factors_mask = delete_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation - Record removed from {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Delete operation - Record removed"
            
            # Updates (U) are medium risk by default if not already high risk
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                # Provide context about which table is being modified
                empty_factors_mask = update_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation - Existing record modified in {x[SESSION_TABLE_COL]} table", axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = "Update operation - Existing record modified"
        
        # Medium risk classification for specific activity patterns
        # Data browser on non-sensitive tables
        if SESSION_TCODE_COL in risk_df.columns and SESSION_TABLE_COL in risk_df.columns:
            browser_mask = (risk_df[SESSION_TCODE_COL] == 'SE16N') & (~risk_df[SESSION_TABLE_COL].isin(sensitive_tables)) & (risk_df['risk_level'] == 'Low')
            if any(browser_mask):
                risk_df.loc[browser_mask, 'risk_level'] = 'Medium'
                risk_df.loc[browser_mask, 'risk_factors'] = risk_df.loc[browser_mask].apply(
                    lambda x: f"Table browser usage - Direct access to {x[SESSION_TABLE_COL]} table data bypassing application logic", axis=1)
        
        # Table maintenance on non-sensitive tables
        if SESSION_TCODE_COL in risk_df.columns and SESSION_TABLE_COL in risk_df.columns:
            maint_mask = (risk_df[SESSION_TCODE_COL].isin(['SM30', 'SM31'])) & (~risk_df[SESSION_TABLE_COL].isin(sensitive_tables)) & (risk_df['risk_level'] == 'Low')
            if any(maint_mask):
                risk_df.loc[maint_mask, 'risk_level'] = 'Medium'
                risk_df.loc[maint_mask, 'risk_factors'] = risk_df.loc[maint_mask].apply(
                    lambda x: f"Table maintenance - Direct modification of {x[SESSION_TABLE_COL]} table bypassing business logic", axis=1)
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Enhanced risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during enhanced risk assessment: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_data
