"""
Analysis functions for SAP audit logs.

This module provides various analysis functions for detecting patterns,
risks, and suspicious activities in SAP audit logs.
"""

import re
import pandas as pd
from collections import Counter, defaultdict

# Risk levels in order of severity
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]

# Specific patterns to look for in risk descriptions
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
    "debug_with_changes": {
        "pattern": r"debug.*change|change.*debug|debugging.*followed by|during debugging session",
        "description": "Debugging tools used in conjunction with data changes",
        "recommendation": "Review the specific changes made during debugging to verify legitimacy"
    },
    "dynamic_abap": {
        "pattern": r"dynamic ABAP|BU4|custom code execution|ran custom code",
        "description": "Dynamic ABAP code execution (high-risk activity)",
        "recommendation": "Review the specific code that was executed to verify it wasn't malicious"
    },
    "inventory_manipulation": {
        "pattern": r"inventory.*manipulation|inventory.*debug|inventory.*fraud",
        "description": "Inventory data manipulation with debugging tools",
        "recommendation": "Investigate inventory records for integrity and compare with physical counts"
    },
    "se16_with_changes": {
        "pattern": r"SE16.*change|change.*SE16|table browser.*change",
        "description": "Direct table manipulation via SE16",
        "recommendation": "Verify business justification for direct table access"
    }
}

def analyze_risk_distribution(df):
    """
    Analyze the distribution of risk levels in the timeline.
    """
    if df.empty or 'risk_level' not in df.columns:
        return {"error": "No risk level data found"}
    
    # Count risk levels
    risk_counts = df['risk_level'].value_counts().to_dict()
    
    # Ensure all risk levels are represented
    for level in RISK_LEVELS:
        if level not in risk_counts:
            risk_counts[level] = 0
    
    # Calculate percentages
    total = len(df)
    risk_percentages = {level: (count / total * 100) for level, count in risk_counts.items()}
    
    return {
        "counts": risk_counts,
        "percentages": risk_percentages,
        "total": total
    }

def analyze_high_risk_items(df):
    """
    Analyze high-risk items requiring follow-up.
    """
    if df.empty:
        return []
    
    # Filter for high and critical risk items
    high_risk_df = df[df['risk_level'].isin(['Critical', 'High'])]
    
    if high_risk_df.empty:
        return []
    
    # Group high risk items by pattern of interest
    findings = []
    
    for category, pattern_info in HIGH_INTEREST_PATTERNS.items():
        pattern = pattern_info["pattern"]
        # Find items matching this pattern
        matches = high_risk_df[high_risk_df['risk_description'].str.contains(
            pattern, case=False, regex=True, na=False)]
        
        if not matches.empty:
            # Get top examples based on session and user
            examples = []
            
            # Group by session and user to find distinct patterns
            if 'Session ID with Date' in matches.columns and 'User' in matches.columns:
                for (session, user), group in matches.groupby(['Session ID with Date', 'User']):
                    # Get the first example from each session/user combination
                    row = group.iloc[0]
                    
                    # Extract key fields with proper NaN handling
                    tcode = row.get('TCode', 'N/A')
                    table = row.get('Table', 'N/A')
                    event = row.get('Event', 'N/A')
                    
                    # Handle NaN values
                    if pd.isna(tcode):
                        tcode = 'N/A'
                    if pd.isna(table):
                        table = 'N/A'
                    if pd.isna(event):
                        event = 'N/A'
                    
                    # Create a concise example
                    example = {
                        "session": session,
                        "user": user,
                        "tcode": tcode,
                        "table": table,
                        "event": event,
                        "risk_level": row.get('risk_level', 'N/A'),
                        "description": row.get('risk_description', 'N/A')
                    }
                    examples.append(example)
            
            # Add finding with examples
            finding = {
                "category": category,
                "description": pattern_info["description"],
                "recommendation": pattern_info["recommendation"],
                "count": len(matches),
                "examples": examples[:3]  # Limit to top 3 examples
            }
            findings.append(finding)
    
    # Sort findings by count (highest first)
    return sorted(findings, key=lambda x: x["count"], reverse=True)

def analyze_key_users(df):
    """
    Analyze key users with suspicious activities.
    """
    if df.empty or 'User' not in df.columns:
        return []
    
    # Focus on high and critical risk events
    high_risk_df = df[df['risk_level'].isin(['Critical', 'High'])]
    
    if high_risk_df.empty:
        return []
    
    # Count high-risk activities by user
    user_counts = high_risk_df['User'].value_counts().to_dict()
    
    # Get details about each user's activities
    users = []
    for user, count in user_counts.items():
        # Skip empty or NaN users
        if not user or pd.isna(user):
            continue
            
        user_df = high_risk_df[high_risk_df['User'] == user]
        
        # Get types of suspicious activities
        activity_types = []
        for category, pattern_info in HIGH_INTEREST_PATTERNS.items():
            if any(user_df['risk_description'].str.contains(
                pattern_info["pattern"], case=False, regex=True, na=False)):
                activity_types.append(pattern_info["description"])
        
        # Get sessions involved
        sessions = user_df['Session ID with Date'].unique().tolist() if 'Session ID with Date' in user_df.columns else []
        
        # Get transactions used
        transactions = user_df['TCode'].unique().tolist() if 'TCode' in user_df.columns else []
        
        users.append({
            "username": user,
            "high_risk_count": count,
            "activity_types": activity_types,
            "sessions": sessions,
            "transactions": transactions
        })
    
    # Sort by high risk count (descending)
    users.sort(key=lambda x: x["high_risk_count"], reverse=True)
    
    return users

def analyze_debug_activities(dfs):
    """
    Analyze debugging activities.
    """
    timeline_df = dfs.get("timeline", pd.DataFrame())
    debug_df = dfs.get("debug", pd.DataFrame())
    
    result = {
        "total_count": 0,
        "by_type": {},
        "by_user": {},
        "message_codes": {}
    }
    
    # Check for debugging activities in the timeline
    if not timeline_df.empty and 'risk_description' in timeline_df.columns:
        debug_patterns = {
            "dynamic_abap": r"dynamic ABAP|BU4|custom code",
            "debugging": r"debug session|debugging|debugger|debug activity",
            "gateway": r"gateway|RFC|remote function"
        }
        
        for debug_type, pattern in debug_patterns.items():
            count = timeline_df['risk_description'].str.contains(pattern, case=False, regex=True, na=False).sum()
            if count > 0:
                result["by_type"][debug_type] = count
                result["total_count"] += count
        
        # Message code detection
        message_codes = ["CU_M", "CUL", "BUZ", "CUK", "CUN", "CUO", "CUP", "BU4", "DU9"]
        for code in message_codes:
            count = timeline_df['risk_description'].str.contains(code, case=False, regex=False, na=False).sum()
            if count > 0:
                result["message_codes"][code] = count
        
        # Debug flags
        debug_flags = {
            "I!": "Custom code execution",
            "D!": "Standard debugging",
            "G!": "Gateway/RFC access"
        }
        
        for flag, description in debug_flags.items():
            # Check multiple columns that might contain these flags
            columns_to_check = ['risk_description']
            if 'Variable_2' in timeline_df.columns:
                columns_to_check.append('Variable_2')
            if 'Description' in timeline_df.columns:
                columns_to_check.append('Description')
                
            flag_count = 0
            for col in columns_to_check:
                try:
                    # First, ensure we only use str methods on string columns
                    if timeline_df[col].dtype == 'object':
                        # Try to use string methods safely
                        flag_count += timeline_df[col].astype(str).str.contains(f"\\b{flag}\\b", regex=True, na=False).sum()
                except Exception as e:
                    from .utils import log_message
                    log_message(f"Warning: Error checking for debug flags in column {col}: {str(e)}", "WARNING")
                
            if flag_count > 0:
                result["by_type"][f"{flag}_flag"] = flag_count
    
    # Check for debugging activities by user
    if not timeline_df.empty and 'User' in timeline_df.columns and 'risk_description' in timeline_df.columns:
        # Find all rows containing debug-related terms
        debug_mask = timeline_df['risk_description'].str.contains(
            r"debug|BU4|custom code|I!|D!|G!", case=False, regex=True, na=False)
        
        if debug_mask.any():
            debug_by_user = timeline_df[debug_mask].groupby('User').size().to_dict()
            result["by_user"] = debug_by_user
    
    return result

def analyze_session_patterns(df):
    """
    Analyze patterns within sessions.
    """
    if df.empty or 'Session ID with Date' not in df.columns:
        return []
    
    # Find sessions with both debugging and changes
    sessions = []
    
    for session_id, session_df in df.groupby('Session ID with Date'):
        # Skip sessions with too few events
        if len(session_df) < 2:
            continue
        
        # Check for debugging activities
        has_debug = False
        if 'risk_description' in session_df.columns:
            has_debug = session_df['risk_description'].str.contains(
                r"debug|debugger|debugging|BU4|custom code|I!|D!|G!",
                case=False, regex=True, na=False).any()
        
        # Check for data changes
        has_changes = False
        if 'Change_Indicator' in session_df.columns:
            has_changes = session_df['Change_Indicator'].isin(['I', 'U', 'D']).any()
        elif 'risk_description' in session_df.columns:
            has_changes = session_df['risk_description'].str.contains(
                r"insert operation|update operation|delete operation|data (change|modification|deletion)",
                case=False, regex=True, na=False).any()
        
        # Check for stealth changes
        has_stealth_changes = False
        if 'risk_description' in session_df.columns:
            has_stealth_changes = session_df['risk_description'].str.contains(
                r"stealth change|unlogged change|potential unlogged",
                case=False, regex=True, na=False).any()
        
        # If this session has interesting patterns, add it to the list
        if (has_debug and has_changes) or has_stealth_changes:
            user = session_df['User'].iloc[0] if 'User' in session_df.columns else 'Unknown'
            date = re.search(r'\((.*?)\)', session_id)
            date = date.group(1) if date else ""
            
            # Extract key events
            key_events = []
            if has_debug:
                debug_df = session_df[session_df['risk_description'].str.contains(
                    r"debug|debugger|BU4|custom code|I!|D!|G!",
                    case=False, regex=True, na=False)]
                
                if not debug_df.empty:
                    for _, row in debug_df.head(2).iterrows():
                        tcode = row.get('TCode', 'N/A')
                        desc = row.get('risk_description', 'N/A')
                        
                        # Create a simplified description
                        simple_desc = desc
                        if ": " in desc:
                            simple_desc = desc.split(": ")[0]
                        
                        key_events.append(f"Debug activity using {tcode}: {simple_desc}")
            
            if has_changes:
                change_df = session_df[session_df['Change_Indicator'].isin(['I', 'U', 'D'])] if 'Change_Indicator' in session_df.columns else pd.DataFrame()
                
                if not change_df.empty:
                    for _, row in change_df.head(2).iterrows():
                        change_type = row.get('Change_Indicator', 'N/A')
                        table = row.get('Table', 'N/A')
                        field = row.get('Field', 'N/A')
                        
                        # Handle NaN values
                        if pd.isna(change_type): change_type = 'N/A'
                        if pd.isna(table): table = 'N/A'
                        if pd.isna(field): field = 'N/A'
                        
                        change_desc = "Unknown change"
                        if change_type == 'I':
                            change_desc = f"Insert into {table}"
                        elif change_type == 'U':
                            change_desc = f"Update to {table}.{field}"
                        elif change_type == 'D':
                            change_desc = f"Delete from {table}"
                        
                        key_events.append(change_desc)
            
            sessions.append({
                "session_id": session_id,
                "user": user,
                "date": date,
                "event_count": len(session_df),
                "has_debug": has_debug,
                "has_changes": has_changes,
                "has_stealth_changes": has_stealth_changes,
                "key_events": key_events
            })
    
    # Sort by riskiest first (debug + changes, or stealth changes)
    sessions.sort(key=lambda x: (x["has_debug"] and x["has_changes"]) or x["has_stealth_changes"], reverse=True)
    
    return sessions

def analyze_algorithm_improvements(report_data, metadata):
    """
    Analyze improvements in detection algorithms by comparing with previous runs.
    """
    # If no previous runs, initialize
    if not metadata or "runs" not in metadata:
        return {"first_run": True, "improvements": []}
    
    # Sort runs by timestamp
    sorted_runs = sorted(metadata.get("runs", []), key=lambda x: x.get("timestamp", ""), reverse=True)
    
    if not sorted_runs:
        return {"first_run": True, "improvements": []}
    
    latest_run = sorted_runs[0]
    
    # Compare current detection with previous run
    improvements = []
    
    # Compare dynamic ABAP detection
    timeline_df = report_data.get("timeline", pd.DataFrame())
    
    if not timeline_df.empty and 'risk_description' in timeline_df.columns:
        current_bu4_count = timeline_df['risk_description'].str.contains(r"BU4|dynamic ABAP", case=False, regex=True, na=False).sum()
        previous_bu4_count = latest_run.get("detection_counts", {}).get("BU4", 0)
        
        if current_bu4_count > previous_bu4_count:
            improvements.append({
                "category": "Dynamic ABAP Detection",
                "previous": previous_bu4_count,
                "current": current_bu4_count,
                "improvement": current_bu4_count - previous_bu4_count,
                "description": f"Improved detection of dynamic ABAP code execution (BU4 events)"
            })
        
        # Compare debug flag detection
        for flag, desc in [("I!", "Custom Code"), ("D!", "Standard Debug"), ("G!", "Gateway/RFC")]:
            current_flag_count = timeline_df['risk_description'].str.contains(flag, regex=False, na=False).sum()
            previous_flag_count = latest_run.get("detection_counts", {}).get(flag, 0)
            
            if current_flag_count > previous_flag_count:
                improvements.append({
                    "category": f"{desc} Flag Detection",
                    "previous": previous_flag_count,
                    "current": current_flag_count,
                    "improvement": current_flag_count - previous_flag_count,
                    "description": f"Improved detection of {desc} flags ({flag})"
                })
    
    # Sort improvements by magnitude
    improvements.sort(key=lambda x: x["improvement"], reverse=True)
    
    return {
        "first_run": False,
        "improvements": improvements,
        "previous_run_date": latest_run.get("timestamp", "Unknown")
    }

def enrich_with_sysaid_data(report_data, sysaid_df):
    """
    Enrich the audit report data with SysAid helpdesk ticket information
    """
    from .utils import log_message
    
    if sysaid_df.empty:
        log_message("No SysAid data available for enrichment", "WARNING")
        return report_data
        
    timeline_df = report_data.get("timeline", pd.DataFrame())
    
    if timeline_df.empty:
        return report_data
    
    log_message("Enriching audit data with SysAid ticket information")
    
    # Check if SysAid # field exists in the timeline
    if 'SysAid #' not in timeline_df.columns and 'SysAid' not in timeline_df.columns:
        log_message("No SysAid ticket field found in audit data", "WARNING")
        return report_data
    
    # Determine the correct field name
    sysaid_field = 'SysAid #' if 'SysAid #' in timeline_df.columns else 'SysAid'
    
    # Ensure ticket fields are strings for consistent joining
    timeline_df[sysaid_field] = timeline_df[sysaid_field].astype(str)
    
    # Merge SysAid data with the timeline
    merged_df = pd.merge(
        timeline_df,
        sysaid_df,
        left_on=sysaid_field,
        right_on='Ticket',
        how='left'
    )
    
    # Update the report_data with the enriched timeline
    log_message(f"Successfully enriched {merged_df['Ticket'].notna().sum()} rows with SysAid data")
    report_data["timeline"] = merged_df
    
    return report_data
