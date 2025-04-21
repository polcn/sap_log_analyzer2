#!/usr/bin/env python3
"""
SAP Audit Tool - Output Generation Functions

This module contains the Excel output generation functions for the SAP Audit Tool.
"""

import os
import pandas as pd
import xlsxwriter
from datetime import datetime

# Risk assessment configuration
CRITICAL_RISK_COLOR = '#7030A0'  # Purple for Critical
HIGH_RISK_COLOR = '#FFC7CE'      # Red for High
MEDIUM_RISK_COLOR = '#FFEB9C'    # Yellow for Medium
LOW_RISK_COLOR = '#C6EFCE'       # Green for Low
SYSAID_COLOR = '#D9D2E9'         # Light Purple for SysAid ticket information

# --- Essential Columns for Reporting ---
# Define which columns to keep in the output for each sheet
CORRELATED_ESSENTIAL_COLUMNS = [
    'USER',                  # User who made the change
    'Change_Timestamp',      # When the change occurred
    'SM20_Datetime',         # When the audit log recorded it
    'SOURCE TA',             # Transaction code from SM20
    'TCode_CD',              # Transaction code from CDHDR
    'Table_Name',            # Table that was modified
    'Change_Indicator',      # Type of change (Insert/Update/Delete)
    'FIELD NAME',            # Field that was changed
    'OLD VALUE',             # Previous value
    'NEW VALUE',             # New value
    'AUDIT LOG MSG. TEXT',   # Context from audit log
    'DOC.NUMBER',            # Change document reference
    'OBJECT',                # Object class
    'OBJECT VALUE',          # Object ID
    'risk_level',            # Assessed risk level
    'risk_factors'           # Explanation of risk assessment
]

# Essential columns for unmatched change documents
UNMATCHED_CD_ESSENTIAL_COLUMNS = [
    'USER',                  # User who made the change
    'Change_Timestamp',      # When the change occurred
    'TCode_CD',              # Transaction code
    'Table_Name',            # Table that was modified
    'Change_Indicator',      # Type of change
    'FIELD NAME',            # Field that was changed
    'OLD VALUE',             # Previous value
    'NEW VALUE',             # New value
    'DOC.NUMBER',            # Change document reference
    'OBJECT',                # Object class
    'OBJECT VALUE'           # Object ID
]

# Essential columns for unmatched SM20 logs
UNMATCHED_SM20_ESSENTIAL_COLUMNS = [
    'USER',                  # User who performed the action
    'SM20_Datetime',         # When it occurred
    'SOURCE TA',             # Transaction code
    'AUDIT LOG MSG. TEXT',   # Description of the action
    'risk_level',            # Assessed risk level
    'risk_factors'           # Explanation of risk assessment
]

# Essential columns for session-based analysis
SESSION_ESSENTIAL_COLUMNS = [
    'Session ID with Date',  # Session identifier with date
    'User',                  # User who performed the action
    'Datetime',              # When it occurred
    'Source',                # Source system (SM20, CDHDR, CDPOS)
    'TCode',                 # Transaction code
    'Variable_First',        # First Variable Value for Event
    'Variable_2',            # Variable 2 flag/code
    'Variable_Data',         # Variable Data for Message
    'Table',                 # Table that was modified
    'Field',                 # Field that was changed
    'Change_Indicator',      # Type of change
    'Old_Value',             # Previous value
    'New_Value',             # New value
    'Description',           # Description of the action
    'Object',                # Object class
    'Object_ID',             # Object ID
    'Doc_Number',            # Change document reference
    'risk_level',            # Assessed risk level
    'sap_risk_level',        # SAP's native risk classification
    'risk_description',      # Explanation of risk assessment (renamed from risk_factors)
    # SysAid ticket fields - grouped together after risk description
    'SYSAID #',              # SysAid ticket number reference
    'Title',                 # SysAid ticket title
    'SysAid Description',    # SysAid ticket description (renamed to avoid column name conflict)
    'Notes',                 # SysAid ticket notes
    'Request user',          # SysAid ticket requester
    'Process manager',       # SysAid ticket manager
    'Request time'           # SysAid ticket request time
]

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def apply_custom_headers(worksheet, df, wb):
    """Apply custom formatting to Excel worksheet headers based on data source."""
        # Map columns to their source systems
    column_sources = {
        'SM20_Datetime': 'SM20',
        'SOURCE TA': 'SM20',
        'AUDIT LOG MSG. TEXT': 'SM20',
        'Change_Timestamp': 'CDHDR',
        'TCode_CD': 'CDHDR',
        'USER': 'CDHDR',
        'Table_Name': 'CDPOS',
        'FIELD NAME': 'CDPOS',
        'Change_Indicator': 'CDPOS',
        'NEW VALUE': 'CDPOS',
        'OLD VALUE': 'CDPOS',
        'risk_level': 'Generated',
        'risk_description': 'Generated',
        'sap_risk_level': 'Generated',
        'DOC.NUMBER': 'CDHDR',
        'OBJECT': 'CDHDR',
        'OBJECT VALUE': 'CDHDR',
        # Session timeline columns
        'Session ID with Date': 'Generated',
        'User': 'Generated',
        'Datetime': 'Generated',
        'Source': 'Generated',
        'TCode': 'Generated',
        'Variable_First': 'SM20',
        'Variable_2': 'SM20',
        'Variable_Data': 'SM20',
        'Table': 'CDPOS',
        'Field': 'CDPOS',
        'Old_Value': 'CDPOS',
        'New_Value': 'CDPOS',
        'Description': 'SM20',
        'Object': 'CDHDR',
        'Object_ID': 'CDHDR',
        'Doc_Number': 'CDHDR',
        # SysAid ticket fields
        'SYSAID #': 'SysAid',
        'Title': 'SysAid',
        'SysAid Description': 'SysAid',  # Only use the new renamed column for SysAid description
        'Notes': 'SysAid',
        'Request user': 'SysAid',
        'Process manager': 'SysAid',
        'Request time': 'SysAid',
        # Additional fields for expanded SysAid integration
        'SysAid Title': 'SysAid',
        'SysAid Notes': 'SysAid',
        'SysAid Request User': 'SysAid'
    }

    # Define formatting for each source system
    header_fmts_by_source = {
        'SM20': wb.add_format({'bold': True, 'bg_color': '#FFD966', 'border': 1, 'text_wrap': True, 'valign': 'top'}),
        'CDHDR': wb.add_format({'bold': True, 'bg_color': '#9BC2E6', 'border': 1, 'text_wrap': True, 'valign': 'top'}),
        'CDPOS': wb.add_format({'bold': True, 'bg_color': '#C6E0B4', 'border': 1, 'text_wrap': True, 'valign': 'top'}),
        'Generated': wb.add_format({'bold': True, 'bg_color': '#F4B084', 'border': 1, 'text_wrap': True, 'valign': 'top'}),
        'SysAid': wb.add_format({'bold': True, 'bg_color': SYSAID_COLOR, 'border': 1, 'text_wrap': True, 'valign': 'top'})
    }

    # Apply formatting to each column
    for i, col in enumerate(df.columns):
        # Set appropriate column widths based on content type
        width = max(len(str(col)) + 2, 15)
        if "factors" in col.lower() or "rationale" in col.lower() or "description" in col.lower():
            width = 100  # Increased width for more detailed risk descriptions
        elif "Msg" in col or "TEXT" in col or "Description" in col:
            width = 60
        elif col in ("Change_Timestamp", "SM20_Datetime", "Datetime"):
            width = 20
        elif col in ("Table_Name", "Table"):
            width = 25
        elif col == "risk_level":
            width = 10
        elif col == "Session ID with Date":
            width = 25

        # Apply formatting
        source = column_sources.get(col, 'Generated')
        fmt = header_fmts_by_source.get(source)
        worksheet.set_column(i, i, width)
        worksheet.write(0, i, col, fmt)

def generate_excel_output(correlated_df, unmatched_cdpos, unmatched_sm20, session_df, output_file):
    """Generate a formatted Excel output with multiple sheets for audit results."""
    log_message(f"Generating Excel output to {output_file}...")
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        os.makedirs(output_dir, exist_ok=True)

        # Function to clean NaN values from dataframes
        def clean_df(df):
            """
            Ultra-aggressive DataFrame cleaner that ensures no NaN values or 'nan' strings 
            appear in Excel output by any means necessary.
            """
            if df is None or len(df) == 0:
                return df
                
            # Make a copy to avoid modifying original
            df_clean = df.copy()
            
            # First pass: Replace all NaN values with empty strings across all columns
            df_clean = df_clean.fillna('')
            
            # Second pass: Convert ALL columns to strings and replace any 'nan' or 'None' text
            for col in df_clean.columns:
                # Convert to string and handle potential errors
                try:
                    # First convert to string
                    df_clean[col] = df_clean[col].astype(str)
                    
                    # Then use string methods on the series
                    if hasattr(df_clean[col], 'str'):
                        # Replace literal 'nan' strings (case insensitive) with empty string
                        df_clean[col] = df_clean[col].str.replace('nan', '', case=False)
                        
                        # Also replace 'None' strings (case insensitive)
                        df_clean[col] = df_clean[col].str.replace('None', '', case=False)
                        
                        # Replace the string 'NaN' specifically
                        df_clean[col] = df_clean[col].str.replace('NaN', '', case=False)
                except Exception as e:
                    # If there's any error, just convert to string directly
                    df_clean[col] = df_clean[col].apply(lambda x: '' if pd.isna(x) else str(x))
                
                # Fix artifacts where we might end up with weird spacing
                try:
                    if hasattr(df_clean[col], 'str'):
                        df_clean[col] = df_clean[col].str.strip()
                except Exception:
                    pass
                    
                # If we converted a number to an empty string (because it was NaN), 
                # it becomes '', but for display it should stay empty
                try:
                    df_clean[col] = df_clean[col].replace('', '')
                except Exception:
                    pass
            
            return df_clean
        
        # Filter dataframes to include only essential columns
        # Use intersection to handle cases where some columns might not exist
        if correlated_df is not None and len(correlated_df) > 0:
            correlated_cols = [col for col in CORRELATED_ESSENTIAL_COLUMNS if col in correlated_df.columns]
            correlated_filtered = clean_df(correlated_df[correlated_cols].copy())
        else:
            correlated_filtered = pd.DataFrame(columns=CORRELATED_ESSENTIAL_COLUMNS)
        
        if unmatched_cdpos is not None and len(unmatched_cdpos) > 0:
            unmatched_cd_cols = [col for col in UNMATCHED_CD_ESSENTIAL_COLUMNS if col in unmatched_cdpos.columns]
            unmatched_cdpos_filtered = clean_df(unmatched_cdpos[unmatched_cd_cols].copy())
        else:
            unmatched_cdpos_filtered = pd.DataFrame(columns=UNMATCHED_CD_ESSENTIAL_COLUMNS)
        
        if unmatched_sm20 is not None and len(unmatched_sm20) > 0:
            unmatched_sm20_cols = [col for col in UNMATCHED_SM20_ESSENTIAL_COLUMNS if col in unmatched_sm20.columns]
            unmatched_sm20_filtered = clean_df(unmatched_sm20[unmatched_sm20_cols].copy())
        else:
            unmatched_sm20_filtered = pd.DataFrame(columns=UNMATCHED_SM20_ESSENTIAL_COLUMNS)
        
        # Filter session dataframe if it exists
        if session_df is not None and len(session_df) > 0:
            session_cols = [col for col in SESSION_ESSENTIAL_COLUMNS if col in session_df.columns]
            session_filtered = clean_df(session_df[session_cols].copy())
        else:
            session_filtered = pd.DataFrame(columns=SESSION_ESSENTIAL_COLUMNS)

        with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
            wb = writer.book
            
            # Sheet 0: Session Timeline (if available)
            if len(session_filtered) > 0:
                log_message("Creating Session Timeline sheet...")
                session_filtered.to_excel(writer, sheet_name="Session_Timeline", index=False, na_rep="")
                ws_session = writer.sheets["Session_Timeline"]
                apply_custom_headers(ws_session, session_filtered, wb)
                ws_session.autofilter(0, 0, len(session_filtered), len(session_filtered.columns) - 1)
                ws_session.freeze_panes(1, 0)

                # Apply conditional formatting based on risk level
                if 'risk_level' in session_filtered.columns:
                    risk_col_idx = session_filtered.columns.get_loc('risk_level')
                    
                    # Format for Critical risk
                    ws_session.conditional_format(1, 0, len(session_filtered), len(session_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Critical"',
                        'format': wb.add_format({'bg_color': CRITICAL_RISK_COLOR, 'font_color': '#FFFFFF'})
                    })
                    
                    # Format for High risk
                    ws_session.conditional_format(1, 0, len(session_filtered), len(session_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"High"',
                        'format': wb.add_format({'bg_color': HIGH_RISK_COLOR})
                    })
                    
                    # Format for Medium risk
                    ws_session.conditional_format(1, 0, len(session_filtered), len(session_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Medium"',
                        'format': wb.add_format({'bg_color': MEDIUM_RISK_COLOR})
                    })
                    
                    # Format for Low risk
                    ws_session.conditional_format(1, 0, len(session_filtered), len(session_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Low"',
                        'format': wb.add_format({'bg_color': LOW_RISK_COLOR})
                    })

            # Sheet 1: Correlated Events (legacy mode)
            if len(correlated_filtered) > 0:
                log_message("Creating Correlated Events sheet...")
                correlated_filtered.to_excel(writer, sheet_name="Correlated_Events", index=False, na_rep="")
                ws_corr = writer.sheets["Correlated_Events"]
                apply_custom_headers(ws_corr, correlated_filtered, wb)
                ws_corr.autofilter(0, 0, len(correlated_filtered), len(correlated_filtered.columns) - 1)
                ws_corr.freeze_panes(1, 0)

                # Apply conditional formatting based on risk level
                if 'risk_level' in correlated_filtered.columns:
                    risk_col_idx = correlated_filtered.columns.get_loc('risk_level')
                    
                    # Format for High risk
                    ws_corr.conditional_format(1, 0, len(correlated_filtered), len(correlated_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"High"',
                        'format': wb.add_format({'bg_color': HIGH_RISK_COLOR})
                    })
                    
                    # Format for Medium risk
                    ws_corr.conditional_format(1, 0, len(correlated_filtered), len(correlated_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Medium"',
                        'format': wb.add_format({'bg_color': MEDIUM_RISK_COLOR})
                    })
                    
                    # Format for Low risk
                    ws_corr.conditional_format(1, 0, len(correlated_filtered), len(correlated_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Low"',
                        'format': wb.add_format({'bg_color': LOW_RISK_COLOR})
                    })

            # Sheet 2: Unmatched Change Documents
            if len(unmatched_cdpos_filtered) > 0:
                log_message("Creating Unmatched CD Changes sheet...")
                unmatched_cdpos_filtered.to_excel(writer, sheet_name="Unmatched_CD_Changes", index=False, na_rep="")
                ws_unmatch_cd = writer.sheets["Unmatched_CD_Changes"]
                apply_custom_headers(ws_unmatch_cd, unmatched_cdpos_filtered, wb)
                ws_unmatch_cd.autofilter(0, 0, len(unmatched_cdpos_filtered), len(unmatched_cdpos_filtered.columns) - 1)
                ws_unmatch_cd.freeze_panes(1, 0)

            # Sheet 3: Unmatched SM20 Logs
            if len(unmatched_sm20_filtered) > 0:
                log_message("Creating Unmatched SM20 Logs sheet...")
                unmatched_sm20_filtered.to_excel(writer, sheet_name="Unmatched_SM20_Logs", index=False, na_rep="")
                ws_unmatch_sm20 = writer.sheets["Unmatched_SM20_Logs"]
                apply_custom_headers(ws_unmatch_sm20, unmatched_sm20_filtered, wb)
                ws_unmatch_sm20.autofilter(0, 0, len(unmatched_sm20_filtered), len(unmatched_sm20_filtered.columns) - 1)
                ws_unmatch_sm20.freeze_panes(1, 0)

                # Apply conditional formatting based on risk level
                if 'risk_level' in unmatched_sm20_filtered.columns:
                    risk_col_idx = unmatched_sm20_filtered.columns.get_loc('risk_level')
                    
                    # Format for High risk
                    ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20_filtered), len(unmatched_sm20_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"High"',
                        'format': wb.add_format({'bg_color': HIGH_RISK_COLOR})
                    })
                    
                    # Format for Medium risk
                    ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20_filtered), len(unmatched_sm20_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Medium"',
                        'format': wb.add_format({'bg_color': MEDIUM_RISK_COLOR})
                    })
                    
                    # Format for Low risk
                    ws_unmatch_sm20.conditional_format(1, 0, len(unmatched_sm20_filtered), len(unmatched_sm20_filtered.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Low"',
                        'format': wb.add_format({'bg_color': LOW_RISK_COLOR})
                    })

            # Sheet 4: Debug Activities - Always attempt to create regardless of variable fields present
            log_message("Creating Debug Activities sheet...")
            
            # Log which variable fields are present for debugging purposes
            var_fields = [col for col in session_filtered.columns if 'variable' in col.lower() or 'var_' in col.lower()]
            log_message(f"Variable-like fields found: {', '.join(var_fields) if var_fields else 'None'}")
            
            # Create a filter for debug-related activities
            # Create query conditions based on column availability
            conditions = []
            
            # Check for debug markers in Variable_2
            if 'Variable_2' in session_filtered.columns:
                conditions.append(session_filtered['Variable_2'].str.contains('I!|D!|G!', na=False))
            
            # FireFighter accounts with high risk activities
            if 'User' in session_filtered.columns and 'risk_level' in session_filtered.columns:
                conditions.append(
                    (session_filtered['User'].str.startswith('FF_', na=False)) & 
                    (session_filtered['risk_level'].isin(['High', 'Critical']))
                )
            
            # Check for debug mentions in risk description or risk_factors
            risk_desc_col = 'risk_description' if 'risk_description' in session_filtered.columns else 'risk_factors'
            if risk_desc_col in session_filtered.columns:
                conditions.append(
                    session_filtered[risk_desc_col].str.contains('debug session detected|dynamic abap code execution', 
                                                               case=False, na=False)
                )
            
            # Combine conditions with OR logic
            if conditions:
                combined_condition = conditions[0]
                for condition in conditions[1:]:
                    combined_condition = combined_condition | condition
                debug_events = session_filtered[combined_condition]
            else:
                debug_events = pd.DataFrame(columns=session_filtered.columns)
            
            if not debug_events.empty:
                # Convert NaN values to empty strings for better display
                                    
                # Count records by category for analysis
                debug_count = len(debug_events)
                
                # Count debug markers if Variable_2 exists
                true_debug_markers = 0
                if 'Variable_2' in debug_events.columns:
                    true_debug_markers = len(debug_events[debug_events['Variable_2'].str.contains('I!|D!|G!', na=False)])
                
                # Count FireFighter high risk activities
                firefighter_high_risk = 0
                if 'User' in debug_events.columns and 'risk_level' in debug_events.columns:
                    firefighter_high_risk = len(debug_events[
                        (debug_events['User'].str.startswith('FF_', na=False)) & 
                        (debug_events['risk_level'].isin(['High', 'Critical']))
                    ])
                
                log_message(f"Debug activity statistics:")
                log_message(f"  - True debug markers (I!, D!, G!): {true_debug_markers}")
                log_message(f"  - FireFighter high risk activities: {firefighter_high_risk}")
                log_message(f"  - Total debug activities: {debug_count}")
                debug_events_fixed = debug_events.fillna('')
                debug_events_fixed.to_excel(writer, sheet_name="Debug_Activities", index=False, na_rep="")
                ws_debug = writer.sheets["Debug_Activities"]
                apply_custom_headers(ws_debug, debug_events_fixed, wb)
                ws_debug.autofilter(0, 0, len(debug_events), len(debug_events.columns) - 1)
                ws_debug.freeze_panes(1, 0)
                
                # Add special formatting for FireFighter accounts
                ff_format = wb.add_format({'bg_color': '#FF0000', 'font_color': '#FFFFFF'})
                ws_debug.conditional_format(1, 0, len(debug_events), len(debug_events.columns) - 1, {
                    'type': 'formula',
                    'criteria': '=LEFT(C2,3)="FF_"',  # Assumes C is the User column
                    'format': ff_format
                })
                
                # Apply risk level conditional formatting
                if 'risk_level' in debug_events.columns:
                    risk_col_idx = debug_events.columns.get_loc('risk_level')
                    
                    # Format for Critical risk
                    ws_debug.conditional_format(1, 0, len(debug_events), len(debug_events.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Critical"',
                        'format': wb.add_format({'bg_color': '#7030A0', 'font_color': '#FFFFFF'})  # Purple for Critical
                    })
                    
                    # Format for High risk
                    ws_debug.conditional_format(1, 0, len(debug_events), len(debug_events.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"High"',
                        'format': wb.add_format({'bg_color': HIGH_RISK_COLOR})
                    })
                    
                    # Format for Medium risk
                    ws_debug.conditional_format(1, 0, len(debug_events), len(debug_events.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Medium"',
                        'format': wb.add_format({'bg_color': MEDIUM_RISK_COLOR})
                    })
                    
                    # Format for Low risk
                    ws_debug.conditional_format(1, 0, len(debug_events), len(debug_events.columns) - 1, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': '"Low"',
                        'format': wb.add_format({'bg_color': LOW_RISK_COLOR})
                    })
                
                log_message(f"Added {len(debug_events)} debug events to Debug Activities sheet")
            else:
                log_message("No debug events found to display")
                
            # Sheet 5: Summary
            log_message("Creating Summary sheet...")
            
            # Determine which dataframe to use for summary
            if len(session_filtered) > 0 and 'risk_level' in session_filtered.columns:
                summary_source = session_filtered
                mode = "session"
            elif len(correlated_filtered) > 0 and 'risk_level' in correlated_filtered.columns:
                summary_source = correlated_filtered
                mode = "legacy"
            else:
                # Create an empty summary if no risk data available
                summary_source = pd.DataFrame({'risk_level': []})
                mode = "unknown"
            
            # Create summary data
            summary_data = {
                'Category': ['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk', 'Total'],
                'Count': [
                    len(summary_source[summary_source['risk_level'] == 'Critical']),
                    len(summary_source[summary_source['risk_level'] == 'High']),
                    len(summary_source[summary_source['risk_level'] == 'Medium']),
                    len(summary_source[summary_source['risk_level'] == 'Low']),
                    len(summary_source)
                ]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name="Summary", index=False, na_rep="")
            
            # Get summary worksheet
            summary_worksheet = writer.sheets["Summary"]
            
            # Apply header format
            header_format = wb.add_format({
                'bold': True,
                'bg_color': '#4F81BD',
                'font_color': 'white',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            for col_num, col_name in enumerate(summary_df.columns):
                summary_worksheet.write(0, col_num, col_name, header_format)
            
            # Add a chart
            chart = wb.add_chart({'type': 'pie'})
            
            # Configure the chart - FIXED: Only include risk rows (excluding Total)
            chart.add_series({
                'name': 'Risk Distribution',
                'categories': ['Summary', 1, 0, 4, 0],  # Include rows 1-4 (Critical, High, Medium, Low)
                'values': ['Summary', 1, 1, 4, 1],      # Include corresponding values
                'points': [
                    {'fill': {'color': CRITICAL_RISK_COLOR}},  # Critical - Purple
                    {'fill': {'color': HIGH_RISK_COLOR}},      # High - Red
                    {'fill': {'color': MEDIUM_RISK_COLOR}},    # Medium - Yellow
                    {'fill': {'color': LOW_RISK_COLOR}}        # Low - Green
                ]
            })
            
            chart.set_title({'name': 'Risk Distribution'})
            chart.set_style(10)
            
            # Insert the chart into the summary worksheet
            summary_worksheet.insert_chart('D2', chart)
            
            # Add mode information
            summary_worksheet.write(6, 0, "Analysis Mode:", header_format)
            summary_worksheet.write(6, 1, mode.capitalize())
            
            # Add timestamp
            summary_worksheet.write(7, 0, "Generated On:", header_format)
            summary_worksheet.write(7, 1, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Set column widths
            summary_worksheet.set_column(0, 0, 15)
            summary_worksheet.set_column(1, 1, 15)

            # Sheet 5: Header Color Legend
            log_message("Creating Header Legend sheet...")
            legend_df = pd.DataFrame({
                'Source': ['SM20', 'CDHDR', 'CDPOS', 'Generated', 'SysAid'],
                'Description': [
                    'SM20 Security Audit Log fields',
                    'CDHDR Change Document Header fields',
                    'CDPOS Change Document Item fields',
                    'Generated or derived fields by the tool',
                    'SysAid ticket information fields'
                ]
            })
            legend_df.to_excel(writer, sheet_name="Legend_Header_Colors", index=False, na_rep="")
            ws_legend = writer.sheets["Legend_Header_Colors"]

            # Apply colors to legend
            header_colors = {
                'SM20': '#FFD966',
                'CDHDR': '#9BC2E6',
                'CDPOS': '#C6E0B4',
                'Generated': '#F4B084',
                'SysAid': SYSAID_COLOR
            }

            for row_idx in range(len(legend_df)):
                source = legend_df.iloc[row_idx]['Source']
                desc = legend_df.iloc[row_idx]['Description']
                color = header_colors.get(source, '#FFFFFF')
                cell_fmt = wb.add_format({'bg_color': color, 'border': 1, 'text_wrap': True})
                ws_legend.write(row_idx + 1, 0, source, cell_fmt)
                ws_legend.write(row_idx + 1, 1, desc, cell_fmt)

            ws_legend.set_column(0, 0, 15)
            ws_legend.set_column(1, 1, 50)

            log_message(f"Excel output successfully generated: {output_file}")
        return True

    except Exception as e:
        log_message(f"Error generating Excel output: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return False
