#!/usr/bin/env python3
"""
SAP Audit Analyzer

This module automatically analyzes the output of the SAP Audit Tool to provide:
1. A summary of high-risk activities
2. Specific items requiring follow-up with clear explanations
3. Performance metrics comparing detection improvements across runs
4. Detailed recommendations for security investigation

This analyzer is designed to run as the final step in the audit process,
providing immediate insights without requiring manual review.
"""

import os
import sys
import json
import pandas as pd
from datetime import datetime
from collections import Counter, defaultdict
import re
import traceback

# --- Configuration ---
VERSION = "1.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Default file paths (within the main directory)
DEFAULT_REPORT_PATH = os.path.join(SCRIPT_DIR, "SAP_Audit_Report.xlsx")
DEFAULT_ANALYSIS_PATH = os.path.join(SCRIPT_DIR, "SAP_Audit_Analysis.html")
DEFAULT_SUMMARY_PATH = os.path.join(SCRIPT_DIR, "SAP_Audit_Summary.txt")
DEFAULT_METADATA_PATH = os.path.join(SCRIPT_DIR, "SAP_Audit_Metadata.json")

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

# --- Utility Functions ---
def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def load_audit_report(report_path=DEFAULT_REPORT_PATH):
    """
    Load the SAP Audit Report Excel file.
    Returns a dictionary of DataFrames, one per sheet.
    """
    try:
        log_message(f"Loading audit report: {report_path}")
        
        # Read all sheets into a dictionary of DataFrames
        sheets = pd.read_excel(report_path, sheet_name=None)
        
        log_message(f"Loaded audit report with {len(sheets)} sheets")
        
        # Extract the main sheets we need
        result = {
            "timeline": sheets.get("Session_Timeline", pd.DataFrame()),
            "debug": sheets.get("Debug_Activities", pd.DataFrame())
        }
        
        # Check if we have the expected data
        if result["timeline"].empty:
            log_message("Warning: Session_Timeline sheet is empty or missing", "WARNING")
        
        log_message(f"Loaded {len(result['timeline'])} timeline events")
        
        return result
    
    except Exception as e:
        log_message(f"Error loading audit report: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "ERROR")
        return {"timeline": pd.DataFrame(), "debug": pd.DataFrame()}

def load_metadata(metadata_path=DEFAULT_METADATA_PATH):
    """
    Load metadata from previous runs.
    Returns an empty dict if no metadata exists.
    """
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        log_message(f"Error loading metadata: {str(e)}", "WARNING")
        return {}

def save_metadata(metadata, metadata_path=DEFAULT_METADATA_PATH):
    """
    Save run metadata for future comparison.
    """
    try:
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        log_message(f"Saved run metadata to {metadata_path}")
    except Exception as e:
        log_message(f"Error saving metadata: {str(e)}", "WARNING")

def extract_field_value(text, field):
    """
    Extract a field value from a risk description text.
    Example: extract_field_value("User: ADMIN, TCode: SE16", "TCode") would return "SE16"
    """
    if not text or not isinstance(text, str):
        return ""
        
    match = re.search(rf"{field}:\s*([^,\s]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""

# --- Analysis Functions ---
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

def analyze_algorithm_improvements(report_data, metadata_path=DEFAULT_METADATA_PATH):
    """
    Analyze improvements in detection algorithms by comparing with previous runs.
    """
    # Load metadata from previous runs
    previous_runs = load_metadata(metadata_path)
    
    # If no previous runs, initialize
    if not previous_runs:
        return {"first_run": True, "improvements": []}
    
    # Get the latest run
    if "runs" not in previous_runs:
        return {"first_run": True, "improvements": []}
    
    # Sort runs by timestamp
    sorted_runs = sorted(previous_runs.get("runs", []), key=lambda x: x.get("timestamp", ""), reverse=True)
    
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

def update_metadata(report_data, metadata_path=DEFAULT_METADATA_PATH):
    """
    Update metadata with current run information.
    """
    # Load existing metadata
    metadata = load_metadata(metadata_path)
    
    # Initialize if needed
    if "runs" not in metadata:
        metadata["runs"] = []
    
    # Create metadata for current run
    timeline_df = report_data.get("timeline", pd.DataFrame())
    
    current_run = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_counts": {},
        "detection_counts": {},
        "total_events": len(timeline_df)
    }
    
    # Add risk counts
    if not timeline_df.empty and 'risk_level' in timeline_df.columns:
        current_run["risk_counts"] = timeline_df['risk_level'].value_counts().to_dict()
    
    # Add detection counts
    if not timeline_df.empty and 'risk_description' in timeline_df.columns:
        # BU4 detection
        current_run["detection_counts"]["BU4"] = timeline_df['risk_description'].str.contains(
            r"BU4|dynamic ABAP", case=False, regex=True, na=False).sum()
        
        # Flag detection
        for flag in ["I!", "D!", "G!"]:
            current_run["detection_counts"][flag] = timeline_df['risk_description'].str.contains(
                flag, regex=False, na=False).sum()
        
        # Message code detection
        message_codes = ["CU_M", "CUL", "BUZ", "CUK", "CUN", "CUO", "CUP", "DU9"]
        for code in message_codes:
            current_run["detection_counts"][code] = timeline_df['risk_description'].str.contains(
                code, regex=False, na=False).sum()
    
    # Add current run to metadata
    metadata["runs"].insert(0, current_run)
    
    # Limit to 10 most recent runs
    metadata["runs"] = metadata["runs"][:10]
    
    # Save updated metadata
    save_metadata(metadata, metadata_path)
    
    return True

def generate_text_summary(report_data, findings):
    """
    Generate a text summary of the analysis findings.
    """
    # Extract data
    risk_distribution = findings.get("risk_distribution", {})
    high_risk_items = findings.get("high_risk_items", [])
    key_users = findings.get("key_users", [])
    session_patterns = findings.get("session_patterns", [])
    debug_activities = findings.get("debug_activities", {})
    algorithm_improvements = findings.get("algorithm_improvements", {})
    
    # Format the summary
    lines = []
    lines.append("# SAP AUDIT REPORT ANALYSIS SUMMARY")
    lines.append("")
    
    # Add timestamp
    lines.append(f"Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Add risk distribution
    lines.append("## Risk Distribution")
    lines.append("")
    
    risk_counts = risk_distribution.get("counts", {})
    for level in RISK_LEVELS:
        count = risk_counts.get(level, 0)
        lines.append(f"- {level}: {count}")
    
    total = risk_distribution.get("total", 0)
    lines.append(f"- Total Events: {total}")
    lines.append("")
    
    # Add high priority follow-up items
    lines.append("## High Priority Follow-up Items")
    lines.append("")
    
    if high_risk_items:
        for i, item in enumerate(high_risk_items):
            lines.append(f"### {i+1}. {item['description']}")
            lines.append(f"**Count:** {item['count']} occurrences")
            lines.append(f"**Recommendation:** {item['recommendation']}")
            lines.append("")
            
            # Add examples
            if item['examples']:
                lines.append("**Key Examples:**")
                for example in item['examples']:
                    user = example.get('user', 'Unknown')
                    session = example.get('session', 'Unknown')
                    tcode = example.get('tcode', 'N/A')
                    table = example.get('table', 'N/A')
                    
                    lines.append(f"- User {user} in session {session} using {tcode}" + 
                               (f" on table {table}" if table and table != "N/A" else ""))
                lines.append("")
    else:
        lines.append("No high-risk items requiring follow-up were identified.")
        lines.append("")
    
    # Add key users section
    if key_users:
        lines.append("## Key Users with Suspicious Activity")
        lines.append("")
        
        for i, user in enumerate(key_users[:5]):  # Top 5 users
            username = user.get('username', 'Unknown')
            count = user.get('high_risk_count', 0)
            activity_types = user.get('activity_types', [])
            transactions = user.get('transactions', [])
            sessions = user.get('sessions', [])
            
            lines.append(f"### {i+1}. User: {username}")
            lines.append(f"- High-risk activities: {count}")
            
            # Always show activity types section, even if empty
            lines.append("- Activity types:")
            if activity_types:
                for activity in activity_types:
                    lines.append(f"  * {activity}")
            else:
                lines.append("  * No specific activity types identified")
            
            # Always show transactions section
            lines.append("- Key transactions used:")
            if transactions:
                for tx in transactions[:5]:  # Top 5 transactions
                    # Handle NaN values
                    if pd.isna(tx):
                        lines.append("  * N/A")
                    else:
                        lines.append(f"  * {tx}")
            else:
                lines.append("  * N/A")
            
            # Always include sessions section
            lines.append("- Sessions:")
            if sessions:
                for session in sessions[:5]:  # Top 5 sessions
                    if pd.isna(session):
                        lines.append("  * Unknown session")
                    else:
                        lines.append(f"  * {session}")
            else:
                lines.append("  * No specific sessions identified")
            
            lines.append("")
    
    # Add session patterns
    if session_patterns:
        lines.append("## Suspicious Session Patterns")
        lines.append("")
        
        for i, session in enumerate(session_patterns[:5]):  # Top 5 sessions
            session_id = session.get('session_id', 'Unknown')
            user = session.get('user', 'Unknown')
            has_debug = session.get('has_debug', False)
            has_changes = session.get('has_changes', False)
            has_stealth = session.get('has_stealth_changes', False)
            key_events = session.get('key_events', [])
            
            lines.append(f"### {i+1}. Session: {session_id}")
            lines.append(f"- User: {user}")
            
            # Describe the suspicious pattern
            pattern_desc = []
            if has_debug and has_changes:
                pattern_desc.append("Debugging combined with data changes")
            if has_stealth:
                pattern_desc.append("Potential stealth changes")
                
            if pattern_desc:
                lines.append(f"- Pattern: {', '.join(pattern_desc)}")
            
            # Add key events
            if key_events:
                lines.append("- Key activities:")
                for event in key_events:
                    lines.append(f"  * {event}")
            
            lines.append("")
    
    # Add debug activities
    debug_by_type = debug_activities.get('by_type', {})
    if debug_by_type:
        lines.append("## Debug Activity Analysis")
        lines.append("")
        
        # Add summary by type
        for debug_type, count in debug_by_type.items():
            # Format the debug type name
            formatted_type = debug_type.replace('_', ' ').replace('flag', '').strip().title()
            lines.append(f"- {formatted_type}: {count}")
        
        # Add message codes if available
        message_codes = debug_activities.get('message_codes', {})
        if message_codes:
            lines.append("")
            lines.append("**Message Code Detections:**")
            for code, count in message_codes.items():
                lines.append(f"- {code}: {count}")
        
        lines.append("")
    
    # Add algorithm improvements
    if not algorithm_improvements.get('first_run', True):
        improvements = algorithm_improvements.get('improvements', [])
        
        if improvements:
            lines.append("## Detection Algorithm Improvements")
            lines.append("")
            
            lines.append(f"Compared to previous run ({algorithm_improvements.get('previous_run_date', 'unknown date')}):")
            
            for improvement in improvements:
                category = improvement.get('category', '')
                prev = improvement.get('previous', 0)
                curr = improvement.get('current', 0)
                diff = improvement.get('improvement', 0)
                
                lines.append(f"- {category}: {prev} → {curr} (+{diff})")
            
            lines.append("")
    
    # Add conclusion
    lines.append("## Conclusion")
    lines.append("")
    
    # Create a conclusion based on findings
    has_critical_findings = False
    
    if high_risk_items or (risk_counts.get('Critical', 0) > 0) or (risk_counts.get('High', 0) > 0):
        has_critical_findings = True
        
    if has_critical_findings:
        lines.append("This analysis has identified significant security concerns that require follow-up investigation.")
        lines.append("Please review the high-priority items and suspicious user sessions highlighted above.")
    else:
        lines.append("No critical security concerns were identified in this analysis.")
        lines.append("Standard security monitoring and periodic reviews should continue.")
    
    # Join lines and return
    return "\n".join(lines)

def generate_html_report(report_data, findings):
    """
    Generate an HTML report of the analysis findings.
    This provides a more detailed and interactive view than the text summary.
    """
    # Extract data
    risk_distribution = findings.get("risk_distribution", {})
    high_risk_items = findings.get("high_risk_items", [])
    key_users = findings.get("key_users", [])
    session_patterns = findings.get("session_patterns", [])
    debug_activities = findings.get("debug_activities", {})
    algorithm_improvements = findings.get("algorithm_improvements", {})
    
    # Generate HTML
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html lang='en'>")
    html.append("<head>")
    html.append("  <meta charset='UTF-8'>")
    html.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html.append("  <title>SAP Audit Analysis Report</title>")
    html.append("  <style>")
    html.append("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }")
    html.append("    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }")
    html.append("    h2 { color: #2980b9; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }")
    html.append("    h3 { color: #3498db; }")
    html.append("    .risk-Critical { background-color: #ff6b6b; color: white; padding: 2px 6px; border-radius: 3px; }")
    html.append("    .risk-High { background-color: #ffa502; color: white; padding: 2px 6px; border-radius: 3px; }")
    html.append("    .risk-Medium { background-color: #fdcb6e; color: #333; padding: 2px 6px; border-radius: 3px; }")
    html.append("    .risk-Low { background-color: #1dd1a1; color: white; padding: 2px 6px; border-radius: 3px; }")
    html.append("    .container { max-width: 1200px; margin: 0 auto; }")
    html.append("    .card { border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")
    html.append("    .card-header { background-color: #f8f9fa; padding: 10px; margin: -15px -15px 15px; border-bottom: 1px solid #ddd; border-radius: 4px 4px 0 0; }")
    html.append("    .section { margin-bottom: 30px; }")
    html.append("    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }")
    html.append("    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }")
    html.append("    th { background-color: #f2f2f2; }")
    html.append("    tr:hover { background-color: #f5f5f5; }")
    html.append("    .footer { margin-top: 50px; text-align: center; font-size: 0.8em; color: #7f8c8d; }")
    html.append("  </style>")
    html.append("</head>")
    html.append("<body>")
    html.append("  <div class='container'>")
    
    # Header
    html.append("    <h1>SAP Audit Security Analysis Report</h1>")
    html.append(f"    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
    
    # Executive Summary
    html.append("    <div class='section'>")
    html.append("      <h2>Executive Summary</h2>")
    html.append("      <div class='card'>")
    
    # Risk distribution
    risk_counts = risk_distribution.get("counts", {})
    total_events = risk_distribution.get("total", 0)
    
    html.append("        <table>")
    html.append("          <tr>")
    html.append("            <th>Risk Level</th>")
    html.append("            <th>Count</th>")
    html.append("            <th>Percentage</th>")
    html.append("          </tr>")
    
    for level in RISK_LEVELS:
        count = risk_counts.get(level, 0)
        percentage = (count / total_events * 100) if total_events > 0 else 0
        
        html.append("          <tr>")
        html.append(f"            <td><span class='risk-{level}'>{level}</span></td>")
        html.append(f"            <td>{count}</td>")
        html.append(f"            <td>{percentage:.1f}%</td>")
        html.append("          </tr>")
    
    html.append("          <tr>")
    html.append("            <td><strong>Total Events</strong></td>")
    html.append(f"            <td>{total_events}</td>")
    html.append("            <td>100%</td>")
    html.append("          </tr>")
    html.append("        </table>")
    
    # High-level findings
    high_findings_count = len(high_risk_items)
    key_users_count = len(key_users)
    session_patterns_count = len(session_patterns)
    
    html.append("        <h3>Key Findings</h3>")
    html.append("        <ul>")
    html.append(f"          <li>{high_findings_count} high-risk item categories identified</li>")
    html.append(f"          <li>{key_users_count} users with suspicious activity</li>")
    html.append(f"          <li>{session_patterns_count} suspicious session patterns detected</li>")
    
    # Count total high-risk events
    high_risk_event_count = risk_counts.get('Critical', 0) + risk_counts.get('High', 0)
    html.append(f"          <li>{high_risk_event_count} total high-risk events requiring attention</li>")
    
    html.append("        </ul>")
    html.append("      </div>")
    html.append("    </div>")
    
    # High Priority Items
    if high_risk_items:
        html.append("    <div class='section'>")
        html.append("      <h2>High Priority Follow-up Items</h2>")
        
        for i, item in enumerate(high_risk_items):
            html.append("      <div class='card'>")
            html.append(f"        <div class='card-header'><h3>{i+1}. {item['description']}</h3></div>")
            html.append(f"        <p><strong>Count:</strong> {item['count']} occurrences</p>")
            html.append(f"        <p><strong>Recommendation:</strong> {item['recommendation']}</p>")
            
            # Add examples
            if item['examples']:
                html.append("        <h4>Key Examples:</h4>")
                html.append("        <table>")
                html.append("          <tr>")
                html.append("            <th>User</th>")
                html.append("            <th>Session</th>")
                html.append("            <th>TCode</th>")
                html.append("            <th>Risk Level</th>")
                html.append("          </tr>")
                
                for example in item['examples']:
                    user = example.get('user', 'Unknown')
                    session = example.get('session', 'Unknown')
                    tcode = example.get('tcode', 'N/A')
                    risk_level = example.get('risk_level', 'N/A')
                    
                    # Handle NaN values
                    if pd.isna(user): user = 'Unknown'
                    if pd.isna(session): session = 'Unknown'
                    if pd.isna(tcode): tcode = 'N/A'
                    if pd.isna(risk_level): risk_level = 'N/A'
                    
                    html.append("          <tr>")
                    html.append(f"            <td>{user}</td>")
                    html.append(f"            <td>{session}</td>")
                    html.append(f"            <td>{tcode}</td>")
                    html.append(f"            <td><span class='risk-{risk_level}'>{risk_level}</span></td>")
                    html.append("          </tr>")
                
                html.append("        </table>")
            
            html.append("      </div>")
        
        html.append("    </div>")
    
    # Key Users Section
    if key_users:
        html.append("    <div class='section'>")
        html.append("      <h2>Key Users with Suspicious Activity</h2>")
        
        for i, user in enumerate(key_users[:5]):  # Top 5 users
            username = user.get('username', 'Unknown')
            count = user.get('high_risk_count', 0)
            activity_types = user.get('activity_types', [])
            transactions = user.get('transactions', [])
            sessions = user.get('sessions', [])
            
            html.append("      <div class='card'>")
            html.append(f"        <div class='card-header'><h3>{i+1}. User: {username}</h3></div>")
            html.append(f"        <p><strong>High-risk activities:</strong> {count}</p>")
            
            if activity_types:
                html.append("        <p><strong>Activity types:</strong></p>")
                html.append("        <ul>")
                for activity in activity_types:
                    html.append(f"          <li>{activity}</li>")
                html.append("        </ul>")
            
            if transactions:
                html.append("        <p><strong>Key transactions used:</strong></p>")
                html.append("        <ul>")
                for tx in transactions[:5]:  # Top 5 transactions
                    # Handle NaN values
                    if pd.isna(tx):
                        tx_value = "N/A"
                    else:
                        tx_value = tx
                    html.append(f"          <li>{tx_value}</li>")
                html.append("        </ul>")
            
            if sessions:
                html.append("        <p><strong>Sessions:</strong></p>")
                html.append("        <ul>")
                for session in sessions[:5]:  # Top 5 sessions
                    html.append(f"          <li>{session}</li>")
                html.append("        </ul>")
            
            html.append("      </div>")
        
        html.append("    </div>")
    
    # Session Patterns
    if session_patterns:
        html.append("    <div class='section'>")
        html.append("      <h2>Suspicious Session Patterns</h2>")
        
        for i, session in enumerate(session_patterns[:5]):  # Top 5 sessions
            session_id = session.get('session_id', 'Unknown')
            user = session.get('user', 'Unknown')
            has_debug = session.get('has_debug', False)
            has_changes = session.get('has_changes', False)
            has_stealth = session.get('has_stealth_changes', False)
            key_events = session.get('key_events', [])
            
            html.append("      <div class='card'>")
            html.append(f"        <div class='card-header'><h3>{i+1}. Session: {session_id}</h3></div>")
            html.append(f"        <p><strong>User:</strong> {user}</p>")
            
            # Describe the suspicious pattern
            pattern_desc = []
            if has_debug and has_changes:
                pattern_desc.append("Debugging combined with data changes")
            if has_stealth:
                pattern_desc.append("Potential stealth changes")
                
            if pattern_desc:
                html.append(f"        <p><strong>Pattern:</strong> {', '.join(pattern_desc)}</p>")
            
            # Add key events
            if key_events:
                html.append("        <p><strong>Key activities:</strong></p>")
                html.append("        <ul>")
                for event in key_events:
                    html.append(f"          <li>{event}</li>")
                html.append("        </ul>")
            
            html.append("      </div>")
        
        html.append("    </div>")
    
    # Detection Improvements
    if not algorithm_improvements.get('first_run', True):
        improvements = algorithm_improvements.get('improvements', [])
        
        if improvements:
            html.append("    <div class='section'>")
            html.append("      <h2>Detection Algorithm Improvements</h2>")
            html.append("      <div class='card'>")
            html.append(f"        <p>Compared to previous run ({algorithm_improvements.get('previous_run_date', 'unknown date')}):</p>")
            
            html.append("        <table>")
            html.append("          <tr>")
            html.append("            <th>Category</th>")
            html.append("            <th>Previous</th>")
            html.append("            <th>Current</th>")
            html.append("            <th>Improvement</th>")
            html.append("          </tr>")
            
            for improvement in improvements:
                category = improvement.get('category', '')
                prev = improvement.get('previous', 0)
                curr = improvement.get('current', 0)
                diff = improvement.get('improvement', 0)
                
                html.append("          <tr>")
                html.append(f"            <td>{category}</td>")
                html.append(f"            <td>{prev}</td>")
                html.append(f"            <td>{curr}</td>")
                html.append(f"            <td>+{diff}</td>")
                html.append("          </tr>")
            
            html.append("        </table>")
            html.append("      </div>")
            html.append("    </div>")
    
    # Footer
    html.append("    <div class='footer'>")
    html.append(f"      <p>SAP Audit Analyzer v{VERSION}</p>")
    html.append("    </div>")
    
    html.append("  </div>")
    html.append("</body>")
    html.append("</html>")
    
    # Join HTML lines and return
    return "\n".join(html)

def analyze_report(report_path=DEFAULT_REPORT_PATH, summary_path=DEFAULT_SUMMARY_PATH, 
                  analysis_path=DEFAULT_ANALYSIS_PATH, metadata_path=DEFAULT_METADATA_PATH):
    """
    Main function to orchestrate the analysis of an SAP audit report.
    This function orchestrates all analysis steps and generates the outputs.
    
    Args:
        report_path: Path to the SAP audit report Excel file
        summary_path: Path to save the text summary
        analysis_path: Path to save the HTML report
        metadata_path: Path to the metadata file for run tracking
        
    Returns:
        Dictionary of analysis findings
    """
    try:
        # Step 1: Load the audit report
        report_data = load_audit_report(report_path)
        
        # Check if report data is valid
        if not report_data or report_data.get("timeline", pd.DataFrame()).empty:
            log_message("Error: No valid data found in audit report", "ERROR")
            return False
        
        timeline_df = report_data.get("timeline")
        log_message(f"Successfully loaded audit report with {len(timeline_df)} timeline events")
        
        # Step 2: Perform analyses
        findings = {}
        
        # Risk distribution analysis
        findings["risk_distribution"] = analyze_risk_distribution(timeline_df)
        
        # High-risk items analysis
        findings["high_risk_items"] = analyze_high_risk_items(timeline_df)
        
        # Key users analysis
        findings["key_users"] = analyze_key_users(timeline_df)
        
        # Debug activities analysis
        findings["debug_activities"] = analyze_debug_activities(report_data)
        
        # Session patterns analysis
        findings["session_patterns"] = analyze_session_patterns(timeline_df)
        
        # Algorithm improvements analysis
        findings["algorithm_improvements"] = analyze_algorithm_improvements(report_data, metadata_path)
        
        # Step 3: Generate text summary
        text_summary = generate_text_summary(report_data, findings)
        
        # Step 4: Generate HTML report
        html_report = generate_html_report(report_data, findings)
        
        # Step 5: Save outputs
        with open(summary_path, 'w') as f:
            f.write(text_summary)
        log_message(f"Saved text summary to {summary_path}")
        
        with open(analysis_path, 'w') as f:
            f.write(html_report)
        log_message(f"Saved HTML report to {analysis_path}")
        
        # Step 6: Update metadata
        update_metadata(report_data, metadata_path)
        
        # Return findings for potential further processing
        return findings
    
    except Exception as e:
        log_message(f"Error analyzing report: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "ERROR")
        return None

# --- Integration Functions ---
def run_analysis_from_audit_tool(report_path=DEFAULT_REPORT_PATH):
    """
    Function to be called from sap_audit_tool.py as the final step.
    
    Args:
        report_path: Path to the SAP audit report Excel file
        
    Returns:
        True if analysis was successful, False otherwise
    """
    try:
        log_message("Starting automatic analysis of audit report...")
        
        # Run analysis
        findings = analyze_report(report_path)
        
        if findings:
            # Print summary to console
            risk_dist = findings.get("risk_distribution", {})
            risk_counts = risk_dist.get("counts", {})
            
            log_message("Analysis complete. Summary of findings:")
            log_message(f"- Critical: {risk_counts.get('Critical', 0)}")
            log_message(f"- High: {risk_counts.get('High', 0)}")
            log_message(f"- Medium: {risk_counts.get('Medium', 0)}")
            log_message(f"- Low: {risk_counts.get('Low', 0)}")
            
            high_items = findings.get("high_risk_items", [])
            if high_items:
                log_message(f"Found {len(high_items)} types of high-risk activities requiring follow-up")
                
                # Print top findings
                for i, item in enumerate(high_items[:3]):  # Top 3
                    log_message(f"- {item['description']} ({item['count']} occurrences)")
            else:
                log_message("No high-risk activities requiring follow-up were identified")
            
            log_message(f"Detailed analysis saved to {DEFAULT_SUMMARY_PATH} and {DEFAULT_ANALYSIS_PATH}")
            
            return True
        else:
            log_message("Analysis failed or produced no results", "WARNING")
            return False
    
    except Exception as e:
        log_message(f"Error running analysis: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "ERROR")
        return False

# --- Main Function ---
def main():
    """
    Main function when this module is run as a script.
    """
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SAP Audit Analyzer')
    parser.add_argument('--report', '-r', default=DEFAULT_REPORT_PATH,
                        help=f'Path to SAP audit report (default: {DEFAULT_REPORT_PATH})')
    parser.add_argument('--summary', '-s', default=DEFAULT_SUMMARY_PATH,
                        help=f'Path to save text summary (default: {DEFAULT_SUMMARY_PATH})')
    parser.add_argument('--html', '-html', default=DEFAULT_ANALYSIS_PATH,
                        help=f'Path to save HTML report (default: {DEFAULT_ANALYSIS_PATH})')
    parser.add_argument('--metadata', '-m', default=DEFAULT_METADATA_PATH,
                        help=f'Path to metadata file (default: {DEFAULT_METADATA_PATH})')
    
    args = parser.parse_args()
    
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT ANALYZER v{} ".format(VERSION).center(80, "*") + "\n"
    banner += " Automated Security Risk Analysis ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    # Run analysis
    start_time = datetime.now()
    findings = analyze_report(args.report, args.summary, args.html, args.metadata)
    elapsed_time = (datetime.now() - start_time).total_seconds()
    
    if findings:
        log_message(f"Analysis complete in {elapsed_time:.2f} seconds.")
        
        # Print report paths
        print(f"\nText summary saved to: {os.path.abspath(args.summary)}")
        print(f"HTML report saved to: {os.path.abspath(args.html)}")
        
        return 0
    else:
        log_message("Analysis failed", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
