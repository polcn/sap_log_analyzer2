"""
Reporting functions for SAP audit log analysis.

This module provides functions for generating reports in various formats
(text, HTML) from SAP audit analysis findings.
"""

import os
import pandas as pd
from datetime import datetime

from .utils import log_message, DEFAULT_SUMMARY_PATH, DEFAULT_ANALYSIS_PATH

# Risk levels in order of severity 
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]

def generate_text_summary(report_data, findings, summary_path=DEFAULT_SUMMARY_PATH):
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
    if algorithm_improvements.get("first_run", True):
        lines.append("## Algorithm Performance")
        lines.append("")
        lines.append("This is the first analysis run. Future runs will show algorithm improvements.")
        lines.append("")
    elif algorithm_improvements.get("improvements", []):
        lines.append("## Algorithm Improvements")
        lines.append("")
        lines.append(f"Compared to previous run on {algorithm_improvements.get('previous_run_date', 'Unknown')}:")
        lines.append("")
        
        for improvement in algorithm_improvements.get("improvements", []):
            lines.append(f"- {improvement['description']}: {improvement['improvement']} more detections")
        
        lines.append("")
    
    # Add SysAid ticket info if available
    timeline_df = report_data.get("timeline", pd.DataFrame())
    if 'title' in timeline_df.columns and 'description' in timeline_df.columns:
        lines.append("## SysAid Ticket Integration")
        lines.append("")
        
        # Count events with SysAid data
        sysaid_count = timeline_df['title'].notna().sum()
        
        if sysaid_count > 0:
            lines.append(f"Integrated with {sysaid_count} SysAid tickets")
            
            # List top 5 most common ticket types
            if 'title' in timeline_df.columns:
                title_counts = timeline_df['title'].value_counts().head(5)
                if not title_counts.empty:
                    lines.append("")
                    lines.append("Most common ticket types:")
                    for title, count in title_counts.items():
                        if pd.notna(title):
                            lines.append(f"- {title}: {count} occurrences")
            
            lines.append("")
        else:
            lines.append("No SysAid ticket data was found or matched with the audit events.")
            lines.append("")
    
    # Write to file
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        
        with open(summary_path, 'w') as f:
            f.write('\n'.join(lines))
        
        log_message(f"Text summary saved to {summary_path}")
        return summary_path
    except Exception as e:
        log_message(f"Error saving text summary: {str(e)}", "ERROR")
        return None

def generate_html_report(report_data, findings, analysis_path=DEFAULT_ANALYSIS_PATH):
    """
    Generate an HTML report with detailed analysis findings.
    """
    import pandas as pd
    
    # Extract data
    risk_distribution = findings.get("risk_distribution", {})
    high_risk_items = findings.get("high_risk_items", [])
    key_users = findings.get("key_users", [])
    session_patterns = findings.get("session_patterns", [])
    debug_activities = findings.get("debug_activities", {})
    
    # Start building HTML content
    html_content = []
    
    # Add header and styles
    html_content.extend([
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "    <meta charset='UTF-8'>",
        "    <title>SAP Audit Analysis Report</title>",
        "    <style>",
        "        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }",
        "        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }",
        "        h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }",
        "        h3 { color: #34495e; }",
        "        .container { max-width: 1200px; margin: 0 auto; }",
        "        .summary-box { background-color: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin-bottom: 20px; }",
        "        .warning-box { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; }",
        "        .danger-box { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px; }",
        "        .success-box { background-color: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px; }",
        "        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
        "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "        th { background-color: #f2f2f2; }",
        "        tr:nth-child(even) { background-color: #f9f9f9; }",
        "        .risk-critical { background-color: #f8d7da; color: #721c24; }",
        "        .risk-high { background-color: #fff3cd; color: #856404; }",
        "        .risk-medium { background-color: #d1ecf1; color: #0c5460; }",
        "        .risk-low { background-color: #d4edda; color: #155724; }",
        "        .tag { display: inline-block; padding: 3px 8px; border-radius: 4px; margin-right: 5px; font-size: 12px; }",
        "        .chart-container { width: 100%; height: 300px; margin-bottom: 30px; }",
        "        .footer { margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px; }",
        "        .sysaid-section { background-color: #e8f4fd; padding: 15px; border-radius: 5px; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <div class='container'>"
    ])
    
    # Add report header
    html_content.extend([
        f"        <h1>SAP Audit Analysis Report</h1>",
        f"        <p>Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "        <div class='summary-box'>",
        "            <h3>Report Summary</h3>"
    ])
    
    # Add risk distribution summary
    risk_counts = risk_distribution.get("counts", {})
    risk_percentages = risk_distribution.get("percentages", {})
    total = risk_distribution.get("total", 0)
    
    html_content.append(f"            <p>Total events analyzed: {total}</p>")
    html_content.append("            <p>Risk distribution:</p>")
    html_content.append("            <ul>")
    
    for level in RISK_LEVELS:
        count = risk_counts.get(level, 0)
        percentage = risk_percentages.get(level, 0)
        html_content.append(f"                <li>{level}: {count} ({percentage:.1f}%)</li>")
    
    html_content.append("            </ul>")
    html_content.append("        </div>")
    
    # Add high priority findings
    html_content.append("        <h2>High Priority Follow-up Items</h2>")
    
    if high_risk_items:
        for i, item in enumerate(high_risk_items):
            risk_class = "danger-box" if item['count'] > 5 else "warning-box"
            html_content.extend([
                f"        <div class='{risk_class}'>",
                f"            <h3>{i+1}. {item['description']}</h3>",
                f"            <p><strong>Count:</strong> {item['count']} occurrences</p>",
                f"            <p><strong>Recommendation:</strong> {item['recommendation']}</p>"
            ])
            
            # Add examples
            if item['examples']:
                html_content.append("            <p><strong>Key Examples:</strong></p>")
                html_content.append("            <table>")
                html_content.append("                <tr><th>User</th><th>Session</th><th>TCode</th><th>Table</th><th>Risk</th></tr>")
                
                for example in item['examples']:
                    user = example.get('user', 'Unknown')
                    session = example.get('session', 'Unknown')
                    tcode = example.get('tcode', 'N/A')
                    table = example.get('table', 'N/A')
                    risk = example.get('risk_level', 'N/A')
                    
                    risk_class = f"risk-{risk.lower()}" if risk in ['Critical', 'High', 'Medium', 'Low'] else ""
                    
                    html_content.append(f"                <tr class='{risk_class}'>")
                    html_content.append(f"                    <td>{user}</td>")
                    html_content.append(f"                    <td>{session}</td>")
                    html_content.append(f"                    <td>{tcode}</td>")
                    html_content.append(f"                    <td>{table}</td>")
                    html_content.append(f"                    <td>{risk}</td>")
                    html_content.append("                </tr>")
                
                html_content.append("            </table>")
            
            html_content.append("        </div>")
    else:
        html_content.append("        <p>No high-risk items requiring follow-up were identified.</p>")
    
    # Add key users section
    html_content.append("        <h2>Key Users with Suspicious Activity</h2>")
    
    if key_users:
        html_content.append("        <table>")
        html_content.append("            <tr><th>User</th><th>High-risk Count</th><th>Activity Types</th><th>Key Transactions</th></tr>")
        
        for user in key_users[:10]:  # Top 10 users
            username = user.get('username', 'Unknown')
            count = user.get('high_risk_count', 0)
            activity_types = user.get('activity_types', [])
            transactions = user.get('transactions', [])
            
            activity_html = ", ".join(activity_types) if activity_types else "No specific types"
            
            # Handle NaN values in transactions
            valid_transactions = []
            for tx in transactions[:5]:  # Top 5 transactions
                if not pd.isna(tx):
                    valid_transactions.append(str(tx))
            
            transactions_html = ", ".join(valid_transactions) if valid_transactions else "N/A"
            
            html_content.append("            <tr>")
            html_content.append(f"                <td>{username}</td>")
            html_content.append(f"                <td>{count}</td>")
            html_content.append(f"                <td>{activity_html}</td>")
            html_content.append(f"                <td>{transactions_html}</td>")
            html_content.append("            </tr>")
        
        html_content.append("        </table>")
    else:
        html_content.append("        <p>No users with high-risk activities were identified.</p>")
    
    # Add session patterns section
    html_content.append("        <h2>Suspicious Session Patterns</h2>")
    
    if session_patterns:
        for i, session in enumerate(session_patterns[:5]):  # Top 5 sessions
            session_id = session.get('session_id', 'Unknown')
            user = session.get('user', 'Unknown')
            date = session.get('date', '')
            event_count = session.get('event_count', 0)
            has_debug = session.get('has_debug', False)
            has_changes = session.get('has_changes', False)
            has_stealth = session.get('has_stealth_changes', False)
            key_events = session.get('key_events', [])
            
            # Determine box class based on risk pattern
            box_class = "danger-box" if has_stealth else ("warning-box" if (has_debug and has_changes) else "summary-box")
            
            html_content.extend([
                f"        <div class='{box_class}'>",
                f"            <h3>{i+1}. Session: {session_id}</h3>",
                f"            <p><strong>User:</strong> {user}</p>",
                f"            <p><strong>Date:</strong> {date}</p>",
                f"            <p><strong>Event Count:</strong> {event_count}</p>"
            ])
            
            # Describe the pattern
            pattern_desc = []
            if has_debug and has_changes:
                pattern_desc.append("Debugging combined with data changes")
            if has_stealth:
                pattern_desc.append("Potential stealth changes")
                
            if pattern_desc:
                html_content.append(f"            <p><strong>Pattern:</strong> {', '.join(pattern_desc)}</p>")
            
            # Add key events
            if key_events:
                html_content.append("            <p><strong>Key activities:</strong></p>")
                html_content.append("            <ul>")
                for event in key_events:
                    html_content.append(f"                <li>{event}</li>")
                html_content.append("            </ul>")
            
            html_content.append("        </div>")
    else:
        html_content.append("        <p>No suspicious session patterns were identified.</p>")
    
    # Add SysAid ticket integration section if available
    timeline_df = report_data.get("timeline", pd.DataFrame())
    if 'title' in timeline_df.columns and 'description' in timeline_df.columns:
        sysaid_count = timeline_df['title'].notna().sum()
        
        if sysaid_count > 0:
            html_content.append("        <h2>SysAid Ticket Integration</h2>")
            html_content.append("        <div class='sysaid-section'>")
            html_content.append(f"            <p>Successfully integrated with {sysaid_count} SysAid tickets</p>")
            
            # Show sample ticket details
            if sysaid_count > 0:
                # Get a sample row with ticket data
                sample_rows = timeline_df[timeline_df['title'].notna()].head(3)
                
                if not sample_rows.empty:
                    html_content.append("            <h3>Sample Ticket Data</h3>")
                    html_content.append("            <table>")
                    html_content.append("                <tr><th>SAP Event</th><th>Ticket</th><th>Title</th><th>Requestor</th></tr>")
                    
                    for _, row in sample_rows.iterrows():
                        ticket = row.get('Ticket', 'N/A')
                        title = row.get('title', 'N/A')
                        event = row.get('Event', row.get('Description', 'Unknown Event'))
                        requestor = row.get('request user', 'N/A')
                        
                        html_content.append("                <tr>")
                        html_content.append(f"                    <td>{event}</td>")
                        html_content.append(f"                    <td>{ticket}</td>")
                        html_content.append(f"                    <td>{title}</td>")
                        html_content.append(f"                    <td>{requestor}</td>")
                        html_content.append("                </tr>")
                    
                    html_content.append("            </table>")
            
            html_content.append("        </div>")
    
    # Add footer and close tags
    html_content.extend([
        "        <div class='footer'>",
        "            <p>Generated by SAP Audit Analyzer</p>",
        "        </div>",
        "    </div>",
        "</body>",
        "</html>"
    ])
    
    # Write to file
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(analysis_path), exist_ok=True)
        
        with open(analysis_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html_content))
        
        log_message(f"HTML report saved to {analysis_path}")
        return analysis_path
    except Exception as e:
        log_message(f"Error saving HTML report: {str(e)}", "ERROR")
        return None
