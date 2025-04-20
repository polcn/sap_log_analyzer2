#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions

This module contains improved risk assessment functions with detailed descriptions
for the SAP Audit Tool, with fixes for pattern matching issues and exclusions
for commonly false-positive field names.
"""

import os
import re
from datetime import datetime
import pandas as pd

# Session Timeline columns (from SAP Log Session Merger)
SESSION_TABLE_COL = 'Table'
SESSION_TCODE_COL = 'TCode'
SESSION_FIELD_COL = 'Field'
SESSION_CHANGE_IND_COL = 'Change_Indicator'

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def get_sensitive_tables():
    """Return a list of sensitive tables that should be monitored closely."""
    return [
        # User management tables
        "USR02", "USR03", "USR04", "USR05", "USR06", "USR10", "USR11", "USR12", 
        "USR21", "USGRP", "USAUTH", "USRSYSACTT",
        
        # Authorization tables
        "AGR_USERS", "AGR_1016", "AGR_1251", "AGR_HIER", "USOBT", "USOBX",
        
        # Configuration tables
        "TOBJ", "TOBJT", "T000", "T001", "TSTC", "TACTZ", "TACT",
        
        # Financial tables
        "BKPF", "BSEG", "VBAK", "VBAP", "VBRK", "VBRP", "LFA1", "KNA1",
        
        # Security tables
        "RSECTAB", "RSECACTPRF", "RSECACTTPRF"
    ]

def get_sensitive_table_descriptions():
    """Return detailed descriptions for sensitive tables."""
    return {
        # User management tables
        "USR02": "User password table - Contains encrypted password hashes",
        "USR03": "User authorization data - Links users to authorization profiles",
        "USR04": "User session data - Contains login and session information",
        "USR05": "User parameter table - Contains user configuration settings",
        "USR06": "User master record - Contains core user account data",
        "USR10": "User address data - Contains user contact information",
        "USR11": "User defaults - Contains default configuration for users",
        "USR12": "User authorization values - Contains specific authorization field values",
        "USR21": "User substitution - Contains user substitution settings",
        "USGRP": "User groups - Maps users to security groups",
        "USAUTH": "User authorizations - Contains user authorization data",
        "USRSYSACTT": "User system activity - Tracks user actions in the system",
        
        # Authorization tables
        "AGR_USERS": "Authorization group users - Maps users to authorization groups",
        "AGR_1016": "Authorization objects - Defines authorization object characteristics",
        "AGR_1251": "Authorization profile parameters - Contains profile configuration",
        "AGR_HIER": "Authorization hierarchy - Defines authorization inheritance",
        "USOBT": "Authorization object texts - Contains object descriptions",
        "USOBX": "Authorization object extensions - Contains extended object settings",
        
        # Configuration tables
        "TOBJ": "System objects - Core system object definitions",
        "TOBJT": "System object texts - Descriptions for system objects",
        "T000": "Client table - Contains client configuration",
        "T001": "Company code table - Contains company code configuration",
        "TSTC": "Transaction codes - Maps transaction codes to programs",
        "TACTZ": "User activity table - Tracks user activity timestamps",
        "TACT": "Activity table - Defines system activities",
        
        # Financial tables
        "BKPF": "Accounting document header - Contains financial document headers",
        "BSEG": "Accounting document segment - Contains financial line items",
        "VBAK": "Sales document header - Contains sales order headers",
        "VBAP": "Sales document item - Contains sales order items",
        "VBRK": "Billing document header - Contains invoice headers",
        "VBRP": "Billing document item - Contains invoice line items",
        "LFA1": "Vendor master - Contains vendor master data",
        "KNA1": "Customer master - Contains customer master data",
        
        # Security tables
        "RSECTAB": "Security table - Contains security configuration data",
        "RSECACTPRF": "Security action profile - Contains security policy configurations",
        "RSECACTTPRF": "Security action type profile - Defines security action types"
    }

def get_common_table_descriptions():
    """Return descriptions for common tables that may not be in the sensitive tables list."""
    return {
        # Sales and Distribution tables
        "VBAP": "Sales Document: Item Data - Contains sales order line items",
        "VBAK": "Sales Document: Header Data - Contains sales order header info",
        "VBFA": "Sales Document Flow - Contains sales process flow",
        "VBRK": "Billing Document: Header - Contains billing document headers",
        "VBRP": "Billing Document: Item - Contains billing document line items",
        "LIKP": "Delivery Header - Contains delivery document headers",
        "LIPS": "Delivery Item - Contains delivery document line items",
        
        # Material Management tables
        "MARA": "General Material Data - Contains material master records",
        "MARC": "Plant Data for Material - Contains plant-specific material data",
        "MAKT": "Material Descriptions - Contains material text descriptions",
        "EKKO": "Purchasing Document Header - Contains purchase order headers",
        "EKPO": "Purchasing Document Item - Contains purchase order line items",
        "MSEG": "Document Segment: Material - Contains material movement data",
        "MCHA": "Material Batch Data - Contains batch-specific material information",
        
        # Financial Accounting tables
        "BKPF": "Accounting Document Header - Contains accounting document headers",
        "BSEG": "Accounting Document Segment - Contains accounting document line items",
        "BSID": "Accounting: Secondary Index for Customers - Customer line items",
        "BSIK": "Accounting: Secondary Index for Vendors - Vendor line items",
        "SKA1": "G/L Account Master (Chart of Accounts) - G/L account master data",
        "SKAT": "G/L Account Texts - G/L account descriptions",
        
        # Controlling tables
        "COEP": "CO Document: Line Items - Contains CO postings",
        "COSS": "Cost Centers: Master Data - Contains cost center master records",
        "CSKS": "Cost Center Master Data - Contains cost center information",
        
        # Human Resources tables
        "PA0000": "HR Master Record: Infotype 0000 (Actions) - Employment actions",
        "PA0001": "HR Master Record: Infotype 0001 (Org. Assignment) - Org structure",
        "PA0002": "HR Master Record: Infotype 0002 (Personal Data) - Personal info",
        "PA0008": "HR Master Record: Infotype 0008 (Basic Pay) - Compensation data",
        
        # Plant Maintenance tables
        "EQUI": "Equipment Master - Contains equipment master data",
        "EQKT": "Equipment Texts - Contains equipment descriptions",
        "IFLOT": "Functional Location - Contains functional location master data",
        
        # Address Management tables
        "ADRU": "Address Data Universe - Contains address records for multiple purposes",
        "ADR6": "Address Email Data - Contains email address information",
        
        # Extended Warehouse Management tables
        "/SCWM/S_NQUAN_CD": "EWM Quantity Change Document - Records changes to stock quantities",
        "/SCWM/QUAN": "EWM Quantity Management - Manages warehouse product quantities",
        "/SCDL/DB_PROCH_I": "Supply Chain Process Header Information - Contains process metadata",
        
        # General tables
        "T001": "Company Codes - Contains company code master data",
        "T001W": "Plants/Branches - Contains plant master data",
        "TBSLT": "Purchase Account Assignment Category Texts - Account assignment descriptions",
        "DD03L": "Table Fields - Contains table field definitions",
        "TADIR": "Directory of Repository Objects - Contains R/3 repository objects",
        "TVARVC": "Table of Values for Variables - Contains variable values"
    }

def get_sensitive_tcodes():
    """Return a list of sensitive transaction codes that should be monitored closely."""
    return [
        # User management transactions
        "SU01", "SU10", "SU20", "SU21", "SU22", "SU24", "SU25",
        
        # System administration transactions
        "SM01", "SM02", "SM12", "SM19", "SM30", "SM31", "SM49", "SM59", 
        "SM69", "SICF", "PFCG", "RZ10", "RZ11", "RZ12",
        
        # Security transactions
        "SE16", "SE16N", "SE38", "SE93", "ST01", "ST02", "ST03", "ST05", "STAUTHTRACE",
        
        # Critical configuration transactions
        "STAD", "SPAM", "SPRO", "OB08", "OB28", "OB51", "OB52", "OB58", 
        
        # Financial transactions
        "FBZP", "FB50", "F110", "F-02", "F-22", "XK01", "XK02", "XD01", "XD02"
    ]

def get_sensitive_tcode_descriptions():
    """Return detailed descriptions for sensitive transaction codes."""
    return {
        # User management transactions
        "SU01": "User maintenance - Create, modify, delete user accounts",
        "SU10": "Mass user maintenance - Modify multiple user accounts",
        "SU20": "Authorization maintenance - Define authorization objects",
        "SU21": "Authorization field maintenance - Define authorization fields",
        "SU22": "Authorization default maintenance - Define default values",
        "SU24": "Authorization proposal values - Create authorization proposals",
        "SU25": "Authorization upgrade - Update authorization data after upgrades",
        
        # System administration transactions
        "SM01": "Lock management - Control system-wide locks",
        "SM02": "System messages - Configure system messages",
        "SM12": "Lock entries management - Manage and release system locks",
        "SM19": "Security audit configuration - Setup security logging",
        "SM30": "Table maintenance - View and edit system tables",
        "SM31": "Table maintenance generator - Configure table maintenance",
        "SM49": "Execute external commands - Run OS level commands",
        "SM59": "RFC destinations - Configure remote connections",
        "SM69": "External commands - Define external command settings",
        "SICF": "HTTP services - Configure web services and ICF settings",
        "PFCG": "Role maintenance - Create, modify, delete roles",
        "RZ10": "Profile maintenance - Modify system profiles",
        "RZ11": "Profile parameter maintenance - Change system parameters",
        "RZ12": "Transport management - Configure transports",
        
        # Security transactions
        "SE16": "Data browser - Direct table data access",
        "SE16N": "Enhanced data browser - Direct table access with extended features",
        "SE38": "ABAP editor - Create/modify ABAP programs",
        "SE93": "Transaction maintenance - Create/modify transaction codes",
        "ST01": "System trace - Analyze system performance",
        "ST02": "Memory utilization - Monitor system memory",
        "ST03": "Workload analysis - Performance monitoring",
        "ST05": "SQL trace - Database access monitoring",
        "STAUTHTRACE": "Authorization trace - Track authorization checks",
        
        # Critical configuration transactions
        "STAD": "System log display - View system logs",
        "SPAM": "Support package manager - Install support packages",
        "SPRO": "Customizing - IMG configuration access",
        "OB08": "Account group maintenance - Configure account groups",
        "OB28": "Document type maintenance - Configure document types",
        "OB51": "Document class maintenance - Configure document classes",
        "OB52": "Account type maintenance - Configure account types",
        "OB58": "Number range maintenance - Configure number ranges",
        
        # Financial transactions
        "FBZP": "Payment program configuration - Configure payment processing",
        "FB50": "Post document - Create accounting documents",
        "F110": "Payment run - Process automatic payments",
        "F-02": "Enter document - Create accounting documents",
        "F-22": "Change document - Modify financial documents",
        "XK01": "Create vendor - Add vendor master record",
        "XK02": "Change vendor - Modify vendor master record",
        "XD01": "Create customer - Add customer master record",
        "XD02": "Change customer - Modify customer master record"
    }

def get_common_tcode_descriptions():
    """Return descriptions for common transaction codes that may not be in the sensitive list."""
    return {
        # Sales and Distribution
        "VA01": "Create Sales Order - Creates a new sales order document",
        "VA02": "Change Sales Order - Modifies an existing sales order",
        "VA03": "Display Sales Order - Views sales order information",
        "VL01N": "Create Outbound Delivery - Creates delivery document for goods issue",
        "VL02N": "Change Outbound Delivery - Modifies delivery document",
        "VL32N": "Change Outbound Delivery (Collective) - Modifies multiple delivery documents",
        "VL33N": "Display Outbound Delivery (Collective) - Views multiple delivery documents",
        "VF01": "Create Billing Document - Creates invoice for customer",
        "VF02": "Change Billing Document - Modifies existing invoice",
        "VF03": "Display Billing Document - Views invoice information",
        
        # Materials Management
        "ME21N": "Create Purchase Order - Creates new PO for procurement",
        "ME22N": "Change Purchase Order - Modifies existing PO",
        "ME23N": "Display Purchase Order - Views PO information",
        "MIGO": "Goods Movement - Records goods receipt, issue, transfer",
        "MM01": "Create Material - Creates new material master record",
        "MM02": "Change Material - Modifies material master data",
        "MM03": "Display Material - Views material information",
        "MASS": "Mass Change Processing - Batch updates for multiple records",
        
        # Financial Accounting
        "FB01": "Post Document - Posts financial accounting document",
        "FB03": "Display Document - Views financial document",
        "FBL1N": "Vendor Line Items - Views vendor account transactions",
        "FBL5N": "Customer Line Items - Views customer account transactions",
        "FS10N": "G/L Account Balances - Views general ledger balances",
        "F-02": "Enter G/L Account Document - Creates G/L posting",
        "F-03": "Display G/L Account Document - Views G/L document",
        "FK01": "Create Vendor - Creates new vendor master record",
        "FK02": "Change Vendor - Modifies vendor master data",
        "FD01": "Create Customer - Creates new customer master record",
        "FD02": "Change Customer - Modifies customer master data",
        
        # Human Resources
        "PA30": "Maintain HR Master Data - Updates employee records",
        "PA20": "Display HR Master Data - Views employee information",
        "PA40": "Personnel Actions - Processes employee status changes",
        
        # Production Planning
        "CO01": "Create Production Order - Creates manufacturing order",
        "CO02": "Change Production Order - Modifies production order",
        "CO03": "Display Production Order - Views production information",
        
        # Plant Maintenance
        "IW31": "Create Service Notification - Reports equipment issues",
        "IW32": "Change Service Notification - Updates maintenance notification",
        "IW33": "Display Service Notification - Views maintenance alerts",
        "IW41": "Create Service Order - Creates maintenance work order",
        
        # Extended Warehouse Management
        "/SCWM/MON": "EWM Monitoring - Monitors warehouse processes and status",
        "/SCWM/PRDI": "EWM Product Distribution - Manages product distribution in warehouse",
        "/SCWM/CHM_PRF": "EWM Change Master Profile - Configures warehouse master data profiles",
        "RFC/SCWM/INB_DLV_SAV": "EWM Save Inbound Delivery - Remote function call for delivery saving",
        
        # System Transactions
        "SM50": "Process Overview - Monitors work processes",
        "SM51": "List of SAP Servers - Views system landscape",
        "SM36": "Job Definition - Schedules background jobs",
        "SM37": "Job Overview - Monitors background jobs",
        "SMQ2": "qRFC Monitor - Tracks queued Remote Function Calls",
        "SU53": "Authorization Check - Diagnoses authorization failures",
        "SH02": "Maintain Search Helps - Configures value help dialogs",
        "AL11": "SAP Directory Structure - Views file system directories",
        "S000": "Initial Screen - System entry point menu",
        "SESSION_MANAGER": "Session Manager - Controls multiple SAP sessions",
        
        # General
        "SU3": "User Profile - Maintains user settings",
        "MM60": "Material Where-Used List - Views material usage",
        "SE11": "ABAP Dictionary - Manages database objects",
        "SE80": "Object Navigator - Browses development objects",
        "SMLG": "Logical Systems - Configures system connections"
    }

def get_common_field_descriptions():
    """Return descriptions for common SAP fields."""
    return {
        # Authorization fields
        "ACTVT": "Activity - Defines permitted transaction operations (create, change, display)",
        "AUTH": "Authorization Object - Controls access to system functions",
        "BRGRU": "Authorization Group - Groups users for access control purposes",
        
        # User/account fields
        "BNAME": "User Name - Login ID for system access",
        "USTYP": "User Type - Classification of user account (dialog, system, etc.)",
        "PERSNO": "Personnel Number - Employee identifier in HR system",
        "USGRP": "User Group - Grouping for authorization purposes",
        
        # Document fields
        "BELNR": "Document Number - Identifies accounting documents",
        "BUKRS": "Company Code - Organizational unit in financial accounting",
        "GJAHR": "Fiscal Year - Accounting period year",
        "BLART": "Document Type - Classifies accounting documents",
        "BLDAT": "Document Date - Date shown on original document",
        "BUDAT": "Posting Date - Date for accounting purposes",
        "TDUHR": "Time Stamp - Transaction or record creation time",
        
        # Financial fields
        "WRBTR": "Amount - Monetary value in document currency",
        "DMBTR": "Amount in Local Currency - Monetary value in company code currency",
        "WAERS": "Currency - Currency code for transaction",
        "MWSKZ": "Tax Code - Determines tax calculation",
        "SAKNR": "G/L Account Number - General ledger account identifier",
        "KOSTL": "Cost Center - Cost accounting identifier",
        
        # Sales fields
        "VBELN": "Sales Document Number - Identifies sales transactions",
        "AUART": "Sales Document Type - Classifies sales document",
        "KUNNR": "Customer Number - Identifier for customer account",
        "MATNR": "Material Number - Identifier for material master",
        "KWMENG": "Order Quantity - Amount ordered in sales unit",
        
          # Purchase fields
          "EBELN": "Purchase Document Number - Identifies purchasing documents",
          "LIFNR": "Vendor Number - Identifier for vendor account",
          "KRED": "Vendor Account Number - Unique identifier for vendor master records",
          "KREDI": "Alternate Vendor Account - Alternative vendor identification",
          "KTOKK": "Vendor Account Group - Categorizes vendor accounts by type",
          "XCPDK": "One-time Account Indicator - Identifies vendor as one-time account",
          "EBELP": "Purchase Document Item - Line item in purchase document",
        
        # Material fields
        "WERKS": "Plant - Manufacturing location",
        "LGORT": "Storage Location - Inventory storage identifier",
        "MEINS": "Base Unit of Measure - Standard unit for material",
        "QUAN": "Quantity - Numeric value of items or materials",
        "CAPA": "Capacity - Maximum storage or processing capacity",
        "COO": "Country of Origin - Source country for material/product",
        "HSDAT": "Production Date - Date when material was produced",
        "VFDAT": "Shelf Life Expiration Date - Date when material expires",
        "UNIT_V": "Volume Unit - Unit of measure for volume",
        "UNIT_W": "Weight Unit - Unit of measure for weight",
        "IDPLATE": "Identification Plate - Physical identification marker",
        
        # Status and control fields
        "GBSTK": "Overall Processing Status - Status of document processing",
        "ABSTK": "Rejection Status - Indicates rejected items",
        "STATUS": "Individual Processing Status - Status indicator for processing",
        "VLSTK": "Completeness Status - Indicates document completion level",
        "LOEVM": "Deletion Indicator - Marks record for deletion",
        "SPERR": "Block Indicator - General blocking indicator",
        "SPERM": "Material Block - Blocking reason for material",
        "SPERQ": "Quality Inspection Block - Quality-related blocking",
        "DSTGRP": "Distribution Group - Group for material distribution",
        "FLGDEFAULT": "Default Flag - Indicates default settings",
        "VALID_FROM": "Valid From Date - Start date for record validity",
        "KEY": "Key Field - Generic identifier field",
        
        # Custom fields
        "ZZ1_ORDEREDQTY_DLI": "Custom Ordered Quantity Delivery Item - Quantity ordered per delivery item",
        "ZZ1_ORDEREDQTY_DLIU": "Custom Ordered Quantity Delivery Unit - Unit for ordered quantity"
    }

def get_critical_field_patterns():
    """Return patterns for critical fields that should be monitored closely."""
    patterns = {}
    
    # Authentication and authorization fields
    patterns[r"(?i)PASS(WORD)?"] = "Password field"
    patterns[r"(?i)AUTH(ORIZATION)?"] = "Authorization field"
    patterns[r"(?i)ROLE"] = "Role assignment field"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    patterns[r"(?i)PERM(ISSION)?(?<!SPERM)"] = "Permission field"
    patterns[r"(?i)ACCESS"] = "Access control field"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    patterns[r"(?i)(KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)|PASSWORD)"] = "Security key field"
    patterns[r"(?i)CRED(ENTIAL)?"] = "Credential field"
    
    # Financial fields
    patterns[r"(?i)AMOUNT"] = "Financial amount field"
    patterns[r"(?i)CURR(ENCY)?"] = "Currency field" 
    patterns[r"(?i)BANK"] = "Banking information field"
    patterns[r"(?i)ACCOUNT"] = "Account field"
    patterns[r"(?i)PAYMENT"] = "Payment field"
    
    # Master data fields
    patterns[r"(?i)VENDOR"] = "Vendor master data field"
    patterns[r"(?i)CUSTOMER"] = "Customer master data field"
    patterns[r"(?i)EMPLOYEE"] = "Employee data field"
    
    # System configuration
    patterns[r"(?i)CONFIG"] = "Configuration field"
    patterns[r"(?i)SETTING"] = "System setting field"
    patterns[r"(?i)PARAM(ETER)?"] = "Parameter field"
    
    return patterns

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns."""
    descriptions = {}
    
    # Authentication and authorization fields
    descriptions[r"(?i)PASS(WORD)?"] = "Password/credential modification - Security sensitive change affecting user authentication"
    descriptions[r"(?i)AUTH(ORIZATION)?"] = "Authorization configuration - Security permission change affecting system access control"
    descriptions[r"(?i)ROLE"] = "Role configuration - Security access control change affecting user permissions scope"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    descriptions[r"(?i)PERM(ISSION)?(?<!SPERM)"] = "Permission settings - Access control modification affecting security boundaries"
    descriptions[r"(?i)ACCESS"] = "Access control field - Field controlling system or resource availability"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    descriptions[r"(?i)(KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC)|PASSWORD)"] = "Security key/token - Infrastructure change affecting encryption or authentication"
    descriptions[r"(?i)CRED(ENTIAL)?"] = "Credential field - Authentication data that may grant system access"
    
    # Financial fields
    descriptions[r"(?i)AMOUNT"] = "Financial amount field - Monetary value change affecting financial transactions"
    descriptions[r"(?i)CURR(ENCY)?"] = "Currency field - Financial data type affecting monetary calculations"
    descriptions[r"(?i)BANK"] = "Banking details - Payment routing information change affecting transactions"
    descriptions[r"(?i)ACCOUNT"] = "Account field - Financial or user account record modification"
    descriptions[r"(?i)PAYMENT"] = "Payment field - Financial transaction data affecting money movement"
    
    # Master data fields
    descriptions[r"(?i)VENDOR"] = "Vendor master data field - Supplier information affecting procurement processes"
    descriptions[r"(?i)CUSTOMER"] = "Customer master data field - Client information affecting sales processes"
    descriptions[r"(?i)EMPLOYEE"] = "Employee data field - Personnel information affecting HR processes"
    
    # System configuration
    descriptions[r"(?i)CONFIG"] = "Configuration field - System setting affecting overall system behavior"
    descriptions[r"(?i)SETTING"] = "System setting field - Parameter controlling system functionality"
    descriptions[r"(?i)PARAM(ETER)?"] = "Parameter field - System configuration option affecting behavior"
    
    return descriptions

def get_field_info(field_value, field_descriptions):
    """
    Format field information with description if available.
    
    Args:
        field_value: The field name/value
        field_descriptions: Dictionary of field descriptions
        
    Returns:
        Formatted field info string
    """
    if not isinstance(field_value, str) or pd.isna(field_value) or field_value.strip() == "":
        return "unknown"
        
    field_value = field_value.strip()
    field_desc = field_descriptions.get(field_value.upper(), "")
    
    if field_desc:
        return f"{field_value} ({field_desc.split(' - ')[0]})"
    else:
        return field_value

def get_tcode_info(tcode, common_tcode_descriptions, sensitive_tcode_descriptions):
    """
    Format transaction code information with description if available.
    
    Args:
        tcode: The transaction code
        common_tcode_descriptions: Dictionary of common TCode descriptions
        sensitive_tcode_descriptions: Dictionary of sensitive TCode descriptions
        
    Returns:
        Formatted TCode info string
    """
    if not isinstance(tcode, str) or pd.isna(tcode) or tcode.strip() == "":
        return "unknown"
        
    tcode = tcode.strip()
    tcode_desc = common_tcode_descriptions.get(tcode.upper(), 
                 sensitive_tcode_descriptions.get(tcode.upper(), ""))
    
    if tcode_desc:
        return f"{tcode} ({tcode_desc.split(' - ')[0]})"
    else:
        return tcode

def get_table_info(table, common_table_descriptions, sensitive_table_descriptions):
    """
    Format table information with description if available.
    
    Args:
        table: The table name
        common_table_descriptions: Dictionary of common table descriptions
        sensitive_table_descriptions: Dictionary of sensitive table descriptions
        
    Returns:
        Formatted table info string
    """
    if not isinstance(table, str) or pd.isna(table) or table.strip() == "":
        return "unknown"
        
    table = table.strip()
    table_desc = common_table_descriptions.get(table.upper(), 
                sensitive_table_descriptions.get(table.upper(), ""))
    
    if table_desc:
        return f"{table} ({table_desc.split(' - ')[0]})"
    else:
        return table

def custom_field_risk_assessment(field_name):
    """
    Perform custom risk assessment for fields that need special handling.
    
    Args:
        field_name: The field name to assess
        
    Returns:
        Tuple of (is_high_risk, risk_description) or (False, None) if not high risk
    """
    # Strip whitespace and convert to uppercase for consistent comparison
    field = field_name.strip().upper() if isinstance(field_name, str) else ""
    
    # List of exact fields to exclude from any risk assessment
    exclude_fields = {"KEY", "SPERM", "SPERQ", "QUAN"}
    if field in exclude_fields:
        return False, None
    
    # Custom rules for specific field patterns
    if field.startswith("KEY_") or field.endswith("_KEY") or "SECUR" in field:
        return True, "Security key/token - Infrastructure change affecting encryption or authentication"
    if "PERM" in field and field != "SPERM" and field != "SPERQ":
        return True, "Permission settings - Access control modification affecting security boundaries"
        
    return False, None

def detect_debug_patterns(row):
    """
    Detect debugging and RFC patterns in SM20 logs.
    Separates true debugging activities from normal service interface calls.
    
    Args:
        row: DataFrame row containing potential debug data
        
    Returns:
        Tuple of (risk_level, risk_factors_list)
        Where risk_level can be 'Critical', 'High', 'Medium', 'Low', or None
        And risk_factors_list is a list of risk factor descriptions
    """
    risk_factors = []
    
    # Get values with fallbacks for missing fields
    var_2 = str(row.get('Variable_2', '')) if pd.notna(row.get('Variable_2', '')) else ''
    var_first = str(row.get('Variable_First', '')) if pd.notna(row.get('Variable_First', '')) else ''
    var_data = str(row.get('Variable_Data', '')) if pd.notna(row.get('Variable_Data', '')) else ''
    username = str(row.get('User', '')) if pd.notna(row.get('User', '')) else ''
    
    # TRUE Debug event detection (I!, D!, G! flags)
    if 'I!' in var_2:
        risk_factors.append("Dynamic ABAP code execution detected (I!) - Internal/Insert operation that may bypass normal controls")
        return 'High', risk_factors
        
    if 'D!' in var_2:
        risk_factors.append("Debug session detected (D!) - User debugging program logic and potentially manipulating runtime variables")
        return 'High', risk_factors
    
    # RFC/Gateway detection (G! flag)
    if 'G!' in var_2:
        risk_factors.append("Gateway/RFC call detected (G!) - Remote function call or service interface access")
        return 'High', risk_factors
    
    # FireFighter detection combined with any suspicious activity
    if username.startswith('FF_') and (var_2 in ['I!', 'D!', 'G!'] or 'R3TR' in var_first):
        if var_2 in ['I!', 'D!', 'G!']:  # Only high risk for true debugging
            risk_factors.append(f"FireFighter account performing privileged action ({var_2}) - Elevated risk due to privileged access")
            return 'Critical', risk_factors
        else:
            risk_factors.append(f"FireFighter account accessing service interfaces - Standard but privileged activity")
            return 'Medium', risk_factors
    
    # Service interface detection - normal operations, separate from debugging
    if 'R3TR IWSV' in var_first or 'R3TR IWSG' in var_first:
        risk_factors.append("Service interface access - Standard OData or API gateway activity")
        return 'Low', risk_factors  # Lower risk level for normal operations
    
    # Gateway framework detection - normal operations, separate from debugging  
    if 'R3TR G4BA' in var_first:
        risk_factors.append("Gateway framework access - Standard SAP Gateway activity")
        return 'Low', risk_factors
    
    # OData endpoint patterns - normal operations but potentially sensitive
    if '/sap/opu/odata/' in var_data:
        risk_factors.append("OData endpoint access - API-based data access")
        return 'Medium', risk_factors
    
    return None, risk_factors

def detect_debug_with_changes(session_df):
    """
    Detect debugging activities correlated with data changes in the same session.
    
    Args:
        session_df: DataFrame containing session data
        
    Returns:
        Modified DataFrame with updated risk assessments
    """
    # Create a copy to avoid warning
    df = session_df.copy()
    
    # Group by session ID
    for session_id, session_group in df.groupby('Session ID with Date'):
        # Check for debug flags in Variable_2
        debug_events = session_group[session_group['Variable_2'].isin(['I!', 'D!', 'G!'])]
        
        # Check for change indicators
        change_events = session_group[session_group['Change_Indicator'].isin(['I', 'U', 'D'])]
        
        # If both debug events and changes exist in same session
        if not debug_events.empty and not change_events.empty:
            # Flag all debug events as Critical
            for idx in debug_events.index:
                df.loc[idx, 'risk_level'] = 'Critical'
                current_factors = df.loc[idx, 'risk_factors']
                new_factor = "Debugging activity with data changes in same session - High risk pattern indicating potential data manipulation"
                df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor
            
            # Flag all change events as High
            for idx in change_events.index:
                if df.loc[idx, 'risk_level'] != 'Critical':  # Don't downgrade Critical events
                    df.loc[idx, 'risk_level'] = 'High'
                current_factors = df.loc[idx, 'risk_factors']
                new_factor = "Data change during debug session - Suspicious pattern indicating potential targeted data manipulation"
                df.loc[idx, 'risk_factors'] = current_factors + "; " + new_factor if current_factors else new_factor
    
    return df

def classify_activity_type(row):
    """Classify the activity type based on the row data."""
    if pd.isna(row.get('TCode')) and pd.isna(row.get('Table')):
        return 'Unknown'
    
    # Check for display transactions
    description = str(row.get('Description', '')).upper()
    if 'DISPLAY' in description or 'VIEW' in description or 'SHOW' in description or 'LIST' in description:
        return 'View'
    
    # Check for change indicator
    change_ind = str(row.get('Change_Indicator', '')).strip().upper()
    if change_ind == 'I':
        return 'Create'
    elif change_ind == 'U':
        return 'Update'
    elif change_ind == 'D':
        return 'Delete'
    
    # Check for transaction code categories
    tcode = str(row.get('TCode', '')).strip().upper()
    if tcode.startswith('F') or tcode in ['FB50', 'FB01', 'FB02']:
        return 'Financial'
    elif tcode.startswith('S'):
        return 'System'
    elif tcode.startswith('MM'):
        return 'Material Management'
    elif tcode.startswith('VA'):
        return 'Sales'
    
    return 'Other'

def assess_risk_session(session_data):
    """
    Assess risk for a session timeline.
    Returns a DataFrame with risk assessments.
    
    Note: Data is assumed to be pre-cleaned by the data prep module,
    but minimal cleaning is still done for defensive programming.
    """
    log_message("Assessing risk with improved pattern matching...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Minimal cleaning for defensive programming only
        # (in case data wasn't properly cleaned in the data prep step)
        for col in [SESSION_TABLE_COL, SESSION_TCODE_COL, SESSION_FIELD_COL, SESSION_CHANGE_IND_COL]:
            if col in risk_df.columns and risk_df[col].dtype == 'object':
                # Only clean if we see excessive whitespace
                if (risk_df[col].astype(str).str.strip() != risk_df[col]).any():
                    log_message(f"Note: Found whitespace in {col} column. Performing defensive cleaning.", "WARNING")
                    risk_df[col] = risk_df[col].astype(str).str.strip()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        
        # Get enhanced descriptions
        table_descriptions = get_sensitive_table_descriptions()
        tcode_descriptions = get_sensitive_tcode_descriptions()
        field_descriptions = get_critical_field_pattern_descriptions()
        field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Add activity type classification
        risk_df['activity_type'] = risk_df.apply(classify_activity_type, axis=1)
        
        # Load the common table descriptions dictionary
        common_table_descriptions = get_common_table_descriptions()
        
        # Assess risk based on sensitive tables
        if SESSION_TABLE_COL in risk_df.columns:
            for table in sensitive_tables:
                table_mask = risk_df[SESSION_TABLE_COL].str.upper() == table.upper()
                if any(table_mask):
                    risk_df.loc[table_mask, 'risk_level'] = 'High'
                    description = table_descriptions.get(table, f"Sensitive table '{table}' - Contains critical system data")
                    # Get field descriptions for referencing in the lambda
                    common_field_desc = get_common_field_descriptions()
                    risk_df.loc[table_mask, 'risk_factors'] = risk_df.loc[table_mask].apply(
                        lambda row: f"{description} (Table: {table}" + (f", Field: {get_field_info(row[SESSION_FIELD_COL], common_field_desc)}" if pd.notna(row[SESSION_FIELD_COL]) and row[SESSION_FIELD_COL].strip() != "" else "") + ")",
                        axis=1)
        
        # Load the common transaction code descriptions dictionary
        common_tcode_descriptions = get_common_tcode_descriptions()
        
        # Assess risk based on sensitive transaction codes
        if SESSION_TCODE_COL in risk_df.columns:
            for tcode in sensitive_tcodes:
                tcode_mask = risk_df[SESSION_TCODE_COL].str.upper() == tcode.upper()
                if any(tcode_mask):
                    risk_df.loc[tcode_mask, 'risk_level'] = 'High'
                    description = tcode_descriptions.get(tcode, f"Sensitive transaction '{tcode}' - Privileged system function")
                    # Only update risk factors if not already set by table assessment
                    empty_factors_mask = tcode_mask & (risk_df['risk_factors'] == '')
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = f"{description} (TCode: {tcode})"
        
        # Load the common field descriptions dictionary
        common_field_descriptions = get_common_field_descriptions()
        
        # Assess risk based on critical field patterns with enhanced descriptions and FIXED patterns
        if SESSION_FIELD_COL in risk_df.columns:
            # Handle null values properly
            adjusted_fields = risk_df[SESSION_FIELD_COL].fillna('')
            
            # First apply custom field assessment to handle special cases
            for idx, row in risk_df.iterrows():
                field_value = row[SESSION_FIELD_COL] if pd.notna(row[SESSION_FIELD_COL]) else ""
                is_high_risk, risk_desc = custom_field_risk_assessment(field_value)
                
                if is_high_risk and risk_desc:
                    risk_df.loc[idx, 'risk_level'] = 'High'
                    # Only update if risk factors not already set
                    if risk_df.loc[idx, 'risk_factors'] == '':
                        # Add field description if available
                        field_desc = common_field_descriptions.get(field_value.upper(), "")
                        field_info = f"{field_value}"
                        if field_desc:
                            field_info = f"{field_value} ({field_desc.split(' - ')[0]})"
                        
                        risk_df.loc[idx, 'risk_factors'] = f"{risk_desc} (Field: {field_info})"
            
            # Skip specific fields like "KEY" that should be excluded
            exclude_fields = ["KEY", "SPERM", "SPERQ", "QUAN"]
            exclude_mask = ~adjusted_fields.str.upper().isin([f.upper() for f in exclude_fields])
            
            # Then apply pattern matching for remaining fields
            for pattern, basic_desc in field_patterns.items():
                # Use word-bounded patterns to avoid false matches, and skip excluded fields
                pattern_mask = adjusted_fields.str.contains(pattern, regex=True, na=False) & exclude_mask
                if any(pattern_mask):
                    risk_df.loc[pattern_mask, 'risk_level'] = 'High'
                    description = field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                    # Only update risk factors if not already set by table/tcode assessment
                    empty_factors_mask = pattern_mask & (risk_df['risk_factors'] == '')
                    # Include the actual field name that matched the pattern with description if available
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"{description} (Field: {get_field_info(x[SESSION_FIELD_COL], common_field_descriptions)})", 
                        axis=1)
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            mask = risk_df['display_but_changed']
            if any(mask):
                risk_df.loc[mask, 'risk_level'] = 'High'
                empty_factors_mask = mask & (risk_df['risk_factors'] == '')
                risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Display transaction with changes (TCode: {get_tcode_info(x[SESSION_TCODE_COL], common_tcode_descriptions, tcode_descriptions)}) - Activity logged as view-only but includes data modifications",
                    axis=1)
        
        # Assess risk based on change indicator - using stripped values for comparison
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) operations
            insert_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'I'
            if any(insert_mask):
                risk_df.loc[insert_mask, 'risk_level'] = 'High'
                empty_factors_mask = insert_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation - New record created in {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Insert operation (Change: {x[SESSION_CHANGE_IND_COL]}) - New record created", axis=1)
            
            # Delete (D) operations
            delete_mask = risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'D'
            if any(delete_mask):
                risk_df.loc[delete_mask, 'risk_level'] = 'High'
                empty_factors_mask = delete_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation - Record removed from {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Delete operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Record removed", axis=1)
            
            # Updates (U) are medium risk by default
            update_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL].str.upper() == 'U')
            if any(update_mask):
                risk_df.loc[update_mask, 'risk_level'] = 'Medium'
                empty_factors_mask = update_mask & (risk_df['risk_factors'] == '')
                if SESSION_TABLE_COL in risk_df.columns:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation - Existing record modified in {get_table_info(x[SESSION_TABLE_COL], common_table_descriptions, table_descriptions)} table",
                        axis=1)
                else:
                    risk_df.loc[empty_factors_mask, 'risk_factors'] = risk_df.loc[empty_factors_mask].apply(
                        lambda x: f"Update operation (Change: {x[SESSION_CHANGE_IND_COL]}) - Existing record modified", axis=1)
        
        # Apply debugging-specific risk assessment if variable fields are present
        debug_fields_present = all(field in risk_df.columns for field in ['Variable_First', 'Variable_2', 'Variable_Data'])
        if debug_fields_present:
            log_message("Applying debugging pattern detection...")
            
            # Apply individual debug pattern detection to each row
            for idx, row in risk_df.iterrows():
                debug_risk_level, debug_risk_factors = detect_debug_patterns(row)
                
                if debug_risk_level and debug_risk_factors:
                    # Override risk level if debug risk is higher
                    current_level = risk_df.loc[idx, 'risk_level']
                    if (debug_risk_level == 'Critical' or 
                        (debug_risk_level == 'High' and current_level != 'Critical') or
                        (debug_risk_level == 'Medium' and current_level not in ['Critical', 'High'])):
                        risk_df.loc[idx, 'risk_level'] = debug_risk_level
                    
                    # Add debug risk factors to existing ones
                    current_factors = risk_df.loc[idx, 'risk_factors']
                    risk_df.loc[idx, 'risk_factors'] = current_factors + "; " + "; ".join(debug_risk_factors) if current_factors else "; ".join(debug_risk_factors)
            
            # Check for correlated debug and change events
            if 'Session ID with Date' in risk_df.columns:
                log_message("Analyzing debug activity correlation with data changes...")
                risk_df = detect_debug_with_changes(risk_df)
                
                # Count critical risk after debugging analysis
                critical_risk_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
                if critical_risk_count > 0:
                    log_message(f"Found {critical_risk_count} critical risk events from debugging pattern analysis", "WARNING")
        else:
            log_message("Skipping debugging pattern detection - variable fields not present in dataset", "INFO")
            
        # Add risk factors for Low risk items that don't have a factor yet
        low_risk_no_factor_mask = (risk_df['risk_level'] == 'Low') & (risk_df['risk_factors'] == '')
        if any(low_risk_no_factor_mask):
            log_message(f"Adding risk factors to {sum(low_risk_no_factor_mask)} low-risk items")
            
            # Use activity_type to categorize low-risk items
            for idx, row in risk_df[low_risk_no_factor_mask].iterrows():
                activity = row.get('activity_type', 'Unknown')
                tcode = row.get(SESSION_TCODE_COL, 'Unknown') if pd.notna(row.get(SESSION_TCODE_COL)) else 'Unknown'
                table = row.get(SESSION_TABLE_COL, '') if pd.notna(row.get(SESSION_TABLE_COL)) else ''
                
                # Get descriptions if available
                tcode_description = ""
                if tcode != 'Unknown' and tcode.strip() != "":
                    tcode_description = common_tcode_descriptions.get(tcode.upper(), tcode_descriptions.get(tcode.upper(), ""))
                    if tcode_description:
                        tcode_description = f" ({tcode_description.split(' - ')[0]})"
                
                table_description = ""
                if table and pd.notna(table) and table.strip() != '' and table != "nan":
                    table_description = common_table_descriptions.get(table.upper(), table_descriptions.get(table.upper(), ""))
                    if table_description:
                        table_description = f" ({table_description.split(' - ')[0]})"
                
                if activity == 'View':
                    risk_df.loc[idx, 'risk_factors'] = f"Standard view activity (TCode: {tcode}{tcode_description}) - Read-only access to system data"
                elif 'Financial' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard financial transaction (TCode: {tcode}{tcode_description}) - Normal business process"
                elif 'Material Management' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard material management activity (TCode: {tcode}{tcode_description}) - Normal inventory process"
                elif 'Sales' in activity:
                    risk_df.loc[idx, 'risk_factors'] = f"Standard sales activity (TCode: {tcode}{tcode_description}) - Normal business process"
                elif activity == 'Other' and table and pd.notna(table) and table.strip() != '':
                    if pd.notna(table) and table != "nan":
                        risk_df.loc[idx, 'risk_factors'] = f"Non-sensitive table access (Table: {table}{table_description}) - Contains non-sensitive data"
                    else:
                        tcode_str = "" if tcode == "Unknown" or tcode.strip() == "" else f" (TCode: {tcode}{tcode_description})"
                        risk_df.loc[idx, 'risk_factors'] = f"Standard system access{tcode_str} - No table modifications detected"
                elif tcode != 'Unknown' and tcode.strip() != "":
                    risk_df.loc[idx, 'risk_factors'] = f"Standard transaction (TCode: {tcode}{tcode_description}) - Routine business function"
                else:
                    risk_df.loc[idx, 'risk_factors'] = f"Low risk activity - No sensitive data or system changes involved"
        
        # Count risk levels
        critical_risk_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. Critical: {critical_risk_count}, High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return session_data
