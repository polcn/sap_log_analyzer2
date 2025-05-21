#!/usr/bin/env python3
"""
SAP Audit Tool - Reference Data Module

This module contains all reference data used in the SAP Audit Tool risk assessment,
including sensitive tables, transaction codes, field patterns, and event code
classifications. It serves as a central repository for all lookup data.
"""

# --- Table Reference Data ---

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

# --- Transaction Code Reference Data ---

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

# --- Field Reference Data ---

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

# --- SAP Event Code Reference Data ---

def get_sap_event_code_classifications():
    """
    Return a mapping of SAP event codes to their risk classification.
    
    Returns:
        dict: Dictionary mapping event codes to their criticality level
             'Critical', 'Important', or 'Non-Critical'
    """
    return {
        # Critical Events
        'AU2': 'Critical',   # Logon Failed
        'AU4': 'Critical',   # Transaction Start Failed
        'AU6': 'Critical',   # RFC/CPIC Logon Failed
        'AU7': 'Critical',   # User Created
        'AU8': 'Critical',   # User Deleted
        'AU9': 'Critical',   # User Locked
        'AUA': 'Critical',   # User Unlocked
        'AUB': 'Critical',   # User Authorization Changed
        'AUE': 'Critical',   # Audit Configuration Changed
        'AUF': 'Critical',   # Audit Active Changed
        'AUI': 'Critical',   # Audit Filter Created
        'AUJ': 'Critical',   # Audit Filter Deleted
        'AUL': 'Critical',   # Failed RFC Call
        'AUM': 'Critical',   # RFC Authorization Failure
        'AUX': 'Critical',   # Report Start Failed
        'BU1': 'Critical',   # Password Check Failed
        'BU2': 'Critical',   # Password Changed
        'BU4': 'Critical',   # Transport Contains Critical Objects
        'CUK': 'Critical',   # C Debugging Activated
        'CUL': 'Critical',   # Field Content Changed (via Debugger)
        'CUW': 'Critical',   # Program Dynamic Info Requests
        'CUZ': 'Critical',   # Generic Table Access by RFC
        'DU9': 'Critical',   # Direct Table Access
        
        # Important/Severe Events
        'AU1': 'Important',  # Logon Successful
        'AUN': 'Important',  # Authorization Assigned to User
        'AUO': 'Important',  # Authorization Removed from User
        'AUP': 'Important',  # Successful Login After Previous Failure
        'AUT': 'Important',  # User Type Changed
        'AUU': 'Important',  # User Master Changed
        'CUI': 'Important',  # Application Started
        
        # Non-Critical Events
        'AU3': 'Non-Critical',  # Transaction Started
        'AU5': 'Non-Critical',  # RFC/CPIC Logon Successful
        'AUC': 'Non-Critical',  # User Logoff
        'AUK': 'Non-Critical',  # Successful RFC Call
        'AUW': 'Non-Critical',  # Report Started
        'AUY': 'Non-Critical',  # RFC Statistical Record
        'CUX': 'Non-Critical',  # Screen Element Changed
    }

def get_sap_event_code_descriptions():
    """
    Return detailed descriptions of SAP event codes.
    
    Returns:
        dict: Dictionary mapping event codes to their descriptions
    """
    return {
        # User Access Events
        'AU1': "Logon Successful - User successfully authenticated to the system",
        'AU2': "Logon Failed - Authentication attempt failed (invalid credentials, locked user, etc.)",
        'AU5': "RFC/CPIC Logon Successful - Remote system successfully authenticated",
        'AU6': "RFC/CPIC Logon Failed - Remote system authentication attempt failed",
        'AUC': "User Logoff - User session terminated",
        'AUP': "Successful Login After Previous Failure - User logged in after prior failures",
        
        # User Management Events
        'AU7': "User Created - New user account created in the system",
        'AU8': "User Deleted - User account removed from the system",
        'AU9': "User Locked - User account was locked (manually or automatically)",
        'AUA': "User Unlocked - User account lock was removed",
        'AUB': "User Authorization Changed - User's permissions were modified",
        'AUN': "Authorization Assigned to User - New permissions granted to user",
        'AUO': "Authorization Removed from User - Permissions revoked from user",
        'AUT': "User Type Changed - User account type was modified",
        'AUU': "User Master Changed - General changes to user master record",
        
        # Transaction/Report Activities
        'AU3': "Transaction Started - User executed a transaction code",
        'AU4': "Transaction Start Failed - User attempted to execute a transaction but was denied",
        'AUW': "Report Started - Report or program execution initiated",
        'AUX': "Report Start Failed - Report or program failed to execute (often permissions)",
        
        # RFC Activities
        'AUK': "Successful RFC Call - Remote function call executed successfully",
        'AUL': "Failed RFC Call - Remote function call execution failed",
        'AUM': "RFC Authorization Failure - Remote function call denied due to lack of authorization",
        'AUY': "RFC Statistical Record - Statistical information about RFC calls",
        
        # Audit Configuration Events
        'AUE': "Audit Configuration Changed - Changes to audit settings",
        'AUF': "Audit Active Changed - Audit logging was activated or deactivated",
        'AUI': "Audit Filter Created - New filter rules added to audit configuration",
        'AUJ': "Audit Filter Deleted - Filter rules removed from audit configuration",
        
        # Password/Security Events
        'BU1': "Password Check Failed - Invalid password was provided",
        'BU2': "Password Changed - User's password was modified",
        'BU4': "Transport Contains Critical Objects - Transport with security-critical objects",
        
        # Debugging/System Access Events
        'CUI': "Application Started - Application or service launched (often Fiori/web service)",
        'CUK': "C Debugging Activated - Low-level system debugging activated",
        'CUL': "Field Content Changed - Field value modified via debugger",
        'CUW': "Program Dynamic Info Requests - Dynamic program information accessed",
        'CUX': "Screen Element Changed - UI element modification",
        'CUZ': "Generic Table Access by RFC - Remote access to database tables",
        'DU9': "Direct Table Access - Direct access to database tables (often via SE16N)"
    }
