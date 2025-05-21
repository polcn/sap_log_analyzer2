#!/usr/bin/env python3
"""
Fixed SAP Audit Tool - Risk Assessment Functions

This is a completely rebuilt version of the module with proper syntax for all regex patterns.
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
    patterns[r"(?i)\bPASS(WORD)?\b"] = "Password field"
    patterns[r"(?i)\bAUTH(ORIZATION)?\b"] = "Authorization field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ROLE(?![A-Za-z0-9_])"] = "Role assignment field"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    patterns[r"(?i)\bPERM(ISSION)?\b(?<!SPERM)"] = "Permission field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ACCESS(?![A-Za-z0-9_])"] = "Access control field"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    patterns[r"(?i)\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\b"] = "Security key field"
    patterns[r"(?i)\bCRED(ENTIAL)?\b"] = "Credential field"
    
    # Financial fields
    patterns[r"(?i)(?<![A-Za-z0-9_])AMOUNT(?![A-Za-z0-9_])"] = "Financial amount field"
    patterns[r"(?i)\bCURR(ENCY)?\b"] = "Currency field" 
    patterns[r"(?i)(?<![A-Za-z0-9_])BANK(?![A-Za-z0-9_])"] = "Banking information field"
    patterns[r"(?i)(?<![A-Za-z0-9_])ACCOUNT(?![A-Za-z0-9_])"] = "Account field"
    patterns[r"(?i)(?<![A-Za-z0-9_])PAYMENT(?![A-Za-z0-9_])"] = "Payment field"
    
    # Master data fields
    patterns[r"(?i)(?<![A-Za-z0-9_])VENDOR(?![A-Za-z0-9_])"] = "Vendor master data field"
    patterns[r"(?i)(?<![A-Za-z0-9_])CUSTOMER(?![A-Za-z0-9_])"] = "Customer master data field"
    patterns[r"(?i)(?<![A-Za-z0-9_])EMPLOYEE(?![A-Za-z0-9_])"] = "Employee data field"
    
    # System configuration
    patterns[r"(?i)(?<![A-Za-z0-9_])CONFIG(?![A-Za-z0-9_])"] = "Configuration field"
    patterns[r"(?i)(?<![A-Za-z0-9_])SETTING(?![A-Za-z0-9_])"] = "System setting field"
    patterns[r"(?i)\bPARAM(ETER)?\b"] = "Parameter field"
    
    return patterns

def get_critical_field_pattern_descriptions():
    """Return detailed descriptions for critical field patterns."""
    descriptions = {}
    
    # Authentication and authorization fields
    descriptions[r"(?i)\bPASS(WORD)?\b"] = "Password/credential modification - Security sensitive change affecting user authentication"
    descriptions[r"(?i)\bAUTH(ORIZATION)?\b"] = "Authorization configuration - Security permission change affecting system access control"
    descriptions[r"(?i)\bROLE\b"] = "Role configuration - Security access control change affecting user permissions scope"
    # Exclude SPERM which contains PERM but shouldn't trigger this pattern
    descriptions[r"(?i)\bPERM(ISSION)?\b(?<!SPERM)"] = "Permission settings - Access control modification affecting security boundaries"
    descriptions[r"(?i)\bACCESS\b"] = "Access control field - Field controlling system or resource availability"
    # Exclude exact matches for "KEY" as a field name, but catch all other key-related fields
    descriptions[r"(?i)\b(?!KEY$).*KEY(TOKEN|CODE|AUTH|PASS|CRYPT|SEC).*\b"] = "Security key/token - Infrastructure change affecting encryption or authentication"
    descriptions[r"(?i)\bCRED(ENTIAL)?\b"] = "Credential field - Authentication data that may grant system access"
    
    # Financial fields
    descriptions[r"(?i)\bAMOUNT\b"] = "Financial amount field - Monetary value change affecting financial transactions"
    descriptions[r"(?i)\bCURR(ENCY)?\b"] = "Currency field - Financial data type affecting monetary calculations"
    descriptions[r"(?i)\bBANK\b"] = "Banking details - Payment routing information change affecting transactions"
    descriptions[r"(?i)\bACCOUNT\b"] = "Account field - Financial or user account record modification"
    descriptions[r"(?i)\bPAYMENT\b"] = "Payment field - Financial transaction data affecting money movement"
    
    # Master data fields
    descriptions[r"(?i)\bVENDOR\b"] = "Vendor master data field - Supplier information affecting procurement processes"
    descriptions[r"(?i)\bCUSTOMER\b"] = "Customer master data field - Client information affecting sales processes"
    descriptions[r"(?i)\bEMPLOYEE\b"] = "Employee data field - Personnel information affecting HR processes"
    
    # System configuration
    descriptions[r"(?i)\bCONFIG\b"] = "Configuration field - System setting affecting overall system behavior"
    descriptions[r"(?i)\bSETTING\b"] = "System setting field - Parameter controlling system functionality"
    descriptions[r"(?i)\bPARAM(ETER)?\b"] = "Parameter field - System configuration option affecting behavior"
    
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
    Detect debugging and RFC patterns in SM20
