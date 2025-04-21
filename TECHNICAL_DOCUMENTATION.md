# SAP Log Analyzer - Technical Documentation

## Session Definition and Timeline Creation

### Date-Based Session Boundaries

Sessions are now defined based on calendar day boundaries rather than the previous 60-minute window approach. This reflects the reality of user working patterns where activity may continue throughout the day with varying gaps.

#### Implementation Details

In `SAP Log Session Merger.py`, the `assign_session_ids` function has been completely redesigned:

```python
# Add a date column for session grouping
df['_session_date'] = df[time_col].dt.date

# Start a new session if user changes or date changes
if user != prev_user or date != prev_date:
    session_id += 1
```

This ensures that all activity by a user on a given calendar day is treated as a single continuous session, enabling more effective pattern detection across longer timeframes.

## Activity Classification and Risk Assessment

### SE16 Transaction Handling

The system properly handles SE16 transactions that have activity code '02' (change) but don't actually make changes to the system. This is a common pattern in SAP logs where authorization for changes is checked but no changes are made.

#### Implementation Details

In `sap_audit_detectors.py`, the `classify_activity_type` function has been enhanced to handle this case:

```python
# Handle special case: SE16 transactions with SM20 source but no actual changes
if tcode == 'SE16' and source == 'SM20' and old_value == '' and new_value == '':
    # This is likely just an auth check with no actual changes
    if 'ACTIVITY 02' in description and 'AUTH. CHECK: PASSED' in description:
        return 'View'  # Reclassify as View despite the 02 activity
```

This ensures that SE16 transactions used for viewing data, even when they have the '02' activity code, are properly classified as "View" operations rather than changes.

## Enhanced Debugging Detection

### 1. Message Code-Based Debugging Detection

A more precise method for identifying debugging activities has been implemented using specific SM20 message codes. This approach is more reliable than looking for variable flags alone.

#### Implementation Details

The new `detect_debug_message_codes` function in `sap_audit_detectors.py` checks for specific SAP message codes:

```python
DEBUG_MESSAGE_CODES = {
    'CU_M': "Jump to ABAP Debugger",
    'CUL': "Field content changed in debugger",
    'BUZ': "Variable modification in debugger",
    'CUK': "C debugging activated",
    'CUN': "Process stopped from debugger",
    'CUO': "Explicit DB commit/rollback from debugger",
    'CUP': "Non-exclusive debugging session started",
    'BU4': "Dynamic ABAP coding",
    'DU9': "Generic table access (e.g., SE16)",
    'AU4': "Failed transaction start (possible authorization failure)"
}
```

This provides more definitive evidence of debugging activities compared to looking for variable flags like 'D!' which may be less consistently present.

### 2. Authorization Bypass Pattern Detection

The system now detects sophisticated authorization bypass patterns where a user encounters an authorization failure, activates debugging, and then successfully performs a similar action - strongly indicating manipulation of authorization checks.

#### Implementation Details

The new `detect_authorization_bypass` function analyzes sequence patterns in a session:

```python
# Look for the sequence: failed transaction -> debug activation -> successful transaction
for i in range(len(events) - 2):
    # Step 1: Check for failed action/transaction
    is_failed = (message_id_i == 'AU4' or 
                 'AUTHORIZATION FAILURE' in desc_i.upper() or 
                 'AUTH. CHECK: FAILED' in desc_i.upper())
    
    # Step 2: Check if followed by debugging activity
    is_debug = (message_id_j in ['CU_M', 'CUL', 'BUZ', 'CUK', 'CUO'] or 
               any(flag in var_2_j for flag in ['D!', 'I!']))
    
    # Step 3: Check if followed by successful action (similar to the failed one)
    is_similar_action = (tcode_i == tcode_k or
                        (tcode_i in desc_k) or
                        ('AUTH. CHECK: PASSED' in desc_k.upper()))
```

When this pattern is detected, it's flagged as 'Critical' risk since it represents a clear circumvention of security controls.

### 3. Inventory Manipulation Detection

Special focus has been added to detect debugging activities combined with inventory-related changes, particularly targeting potency and valuation fields which are critical for inventory fraud detection.

#### Implementation Details

```python
INVENTORY_SENSITIVE_TABLES = {
    # Material master data
    'MARA': "Material Master Data",
    'MARC': "Plant Data for Material",
    'MBEW': "Material Valuation",
    'EBEW': "Sales Order Stock Valuation",
    'QBEW': "Project Stock Valuation",
    
    # Batch management (potency)
    'MCH1': "Batch Master",
    'MCHA': "Batch Classification Data"
    # ...
}

INVENTORY_CRITICAL_FIELDS = {
    # Potency-related fields
    'POTX1': "Potency value",
    'POTX2': "Potency value",
    # Valuation fields
    'STPRS': "Standard Price",
    'PEINH': "Price Unit",
    'VPRSV': "Price Control"
    # ...
}
```

The `detect_inventory_manipulation` function first checks for debugging activities in a session, then looks for changes to these critical inventory tables or fields.

### 4. Enhanced Stealth Changes Detection

The existing stealth change detection (activity 02 without CDHDR/CDPOS entries) has been enhanced with special consideration for inventory-related tables:

```python
# Find SM20 entries with activity 02 indication
sm20_activity_02_mask = (
    (risk_df['Source'] == 'SM20') & 
    (risk_df['Description'].str.contains('ACTIVITY 02', case=False, na=False)) &
    (risk_df['Description'].str.contains('AUTH. CHECK: PASSED', case=False, na=False))
)

# Focus on inventory tables mentioned in the description
inventory_table_mask = False
for table in INVENTORY_SENSITIVE_TABLES:
    inventory_table_mask |= risk_df['Description'].str.contains(table, case=False, na=False)

# Combined mask for inventory-related stealth changes
inventory_stealth_mask = sm20_activity_02_mask & inventory_table_mask & (...)
```

This allows for more targeted risk assessment specific to inventory valuation changes.

## Dual-Format Risk Descriptions

Risk descriptions follow a consistent dual-format pattern that makes them more accessible to non-technical users while preserving technical details:

```
[Plain English Summary]: [Technical Details]
```

### Implementation Details

Throughout `sap_audit_detectors.py` and `sap_audit_risk_core.py`, risk descriptions have been updated to follow this pattern. For example:

```python
# Before
risk_factors.append("Debug session detected (D!) - User debugging program logic and potentially manipulating runtime variables")

# After
risk_factors.append("System debugging activity: User activated debugging tools that allow viewing and potentially altering how the system processes data. [Technical: Debug session detected (D!) - User debugging program logic and potentially manipulating runtime variables]")
```

This makes the output more useful to both technical and non-technical audiences.

## FireFighter Account Handling

Special handling for FireFighter accounts (those with usernames starting with "FF_") has been removed. All privileged users are now evaluated using the same risk criteria, making the risk assessment more consistent and equitable.

### Implementation Details

In `sap_audit_detectors.py`, the code that specifically checked for usernames starting with "FF_" has been removed and replaced with more general logic that focuses on the activities themselves rather than the account names:

```python
# Before
if username.startswith('FF_') and (var_2 in ['I!', 'D!', 'G!'] or 'R3TR' in var_first):
    if var_2 in ['I!', 'D!', 'G!']:
        risk_factors.append(f"FireFighter account performing privileged action...")
        return 'Critical', risk_factors
    else:
        risk_factors.append(f"FireFighter account accessing service interfaces...")
        return 'Medium', risk_factors

# After
# No special handling for FireFighter accounts as all users are considered privileged
# Instead, focus on the activity indicators themselves
if 'R3TR' in var_first:
    risk_factors.append(f"Service interface access by privileged user...")
    return 'Medium', risk_factors
```

## Multi-layered Risk Assessment Approach

The new implementation uses a multi-layered approach to debugging detection:

1. **Individual Event Analysis**:
   - Variable flag-based detection (D!, I!, G! flags in Variable_2)
   - Message code-based detection (CU_M, CUL, BUZ, etc.)

2. **Session Pattern Analysis**:
   - Authorization bypass pattern
   - Inventory manipulation pattern
   - Debug with changes correlation

3. **Context-Aware Risk Elevation**:
   - Activity type considerations (preserving View classification)
   - Inventory-specific considerations
   - Rule-based risk level determination

This comprehensive approach provides greater accuracy in identifying both simple debugging activities and sophisticated patterns that may indicate security bypasses or fraud attempts.

## Automated Analysis

The system now includes an automated report analyzer that runs as the final step in the audit process, providing:

1. Instant analysis of findings
2. Prioritized follow-up recommendations
3. Tracking of detection algorithm improvements
4. Both text and HTML formatted reports

### Implementation Details

The automated analyzer is implemented in `sap_audit_analyzer.py` and integrated with the main tool in `sap_audit_tool.py`:

```python
# Step 5: Run automated analysis on the output file if analyzer is available
if 'ANALYZER_AVAILABLE' in globals() and ANALYZER_AVAILABLE:
    log_message("Starting automated analysis of audit report...")
    try:
        analysis_success = run_analysis_from_audit_tool(OUTPUT_FILE)
        if analysis_success:
            log_message("Automated analysis completed successfully")
        else:
            log_message("Automated analysis failed or produced no significant results", "WARNING")
    except Exception as e:
        log_message(f"Error running automated analysis: {str(e)}", "ERROR")
```

### Analyzer Features

#### Comprehensive Analysis Types

The analyzer performs multiple specialized analyses:

1. **Risk Distribution**: Statistical breakdown of risk levels
2. **High-Risk Items**: Pattern-based detection of serious security concerns
3. **Key Users**: Identification of users with suspicious activities
4. **Session Patterns**: Detection of suspicious activity sequences within sessions
5. **Debug Activities**: Detailed analysis of debugging techniques
6. **Algorithm Improvements**: Comparison with previous runs to track detection enhancements

#### Pattern-Based Detection

The analyzer uses configurable patterns to identify high-interest security concerns:

```python
HIGH_INTEREST_PATTERNS = {
    "authorization_bypass": {
        "pattern": r"authorization bypass|auth.*bypass|bypass.*auth",
        "description": "Potential authorization control bypass",
        "recommendation": "Investigate user activity to determine if authorization controls were compromised"
    },
    "stealth_changes": {
        "pattern": r"stealth change|unlogged change|change.*no.*record|potential unlogged",
        "description": "Changes with potentially missing audit trail",
        "recommendation": "Verify if actual data changes occurred and why they weren't properly logged"
    },
    # ... additional patterns
}
```

#### Dual-Format Output

The analyzer generates two types of reports:

1. **Text Summary** (`SAP_Audit_Summary.txt`): Concise text-based summary for quick review
2. **HTML Report** (`SAP_Audit_Analysis.html`): Detailed interactive report with color-coding and structured sections

#### Algorithm Improvement Tracking

The analyzer maintains metadata about each run in `SAP_Audit_Metadata.json`, enabling:

- Comparison of detection rates between runs
- Tracking of newly detected patterns
- Measurement of algorithm enhancement effectiveness
