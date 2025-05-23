#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Analysis Module

This module adds additional analysis columns to the SAP audit data:
1. Transaction code descriptions 
2. Event descriptions
3. Table descriptions
4. Analysis flags for key risk areas:
   - Table maintenance activities
   - High-risk transaction codes
   - Change activities
   - Transport-related events
   - Debugging-related events
   - Benign activities
5. Support for observations and conclusions

This module is designed to enhance the output from the risk assessment module
with more detailed information for audit analysis.
"""

import os
import sys
import pandas as pd
from datetime import datetime
import re

# Import configuration
from sap_audit_config import PATHS, COLUMNS, SETTINGS
from sap_audit_utils import (
    log_message, log_section, log_error, handle_exception
)

class SAPAuditAnalyzer:
    """
    Enhanced analysis for SAP audit data.
    
    This class adds additional analysis columns to help with audit reviews,
    including descriptive information and risk flag columns.
    """
    
    def __init__(self, config=None):
        """
        Initialize the analyzer with configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Initialize reference dictionaries
        self.tcode_descriptions = {}
        self.event_descriptions = {}
        self.table_descriptions = {}
        self.high_risk_tcodes = set()
        self.high_risk_tcode_categories = {}
        self.high_risk_tables = set()
        self.high_risk_table_categories = {}
        
        # Load reference data
        self._load_reference_data()
    
    @handle_exception
    def _load_reference_data(self):
        """
        Load reference data from CSV files.
        
        Loads:
        - Transaction code descriptions
        - Event code descriptions
        - Table descriptions
        - High-risk transaction codes
        - High-risk tables
        """
        log_section("Loading Reference Data for Enhanced Analysis")
        
        # Load transaction code descriptions
        try:
            tcodes_file = PATHS.get("tcodes_reference")
            if tcodes_file and os.path.exists(tcodes_file):
                df_tcodes = pd.read_csv(tcodes_file)
                self.tcode_descriptions = dict(zip(df_tcodes["TCode"], df_tcodes["TCode Description"]))
                log_message(f"Loaded {len(self.tcode_descriptions)} transaction code descriptions")
            else:
                # Create demo data for testing
                demo_tcodes = {
                    'SE38': 'ABAP Editor',
                    'SE37': 'Function Builder',
                    'SE24': 'Class Builder',
                    'SE80': 'Object Navigator',
                    'SU01': 'User Maintenance',
                    'PFCG': 'Role Maintenance',
                    'SM30': 'Table Maintenance',
                    'SE16': 'Data Browser',
                    'SE16N': 'Enhanced Data Browser',
                    'VA01': 'Create Sales Order',
                    'VA02': 'Change Sales Order',
                    'VA03': 'Display Sales Order',
                    'MM01': 'Create Material',
                    'MM02': 'Change Material',
                    'MM03': 'Display Material',
                    'ME21': 'Create Purchase Order',
                    'ME23': 'Display Purchase Order',
                    'STMS': 'Transport Management System',
                    'FK01': 'Create Vendor (Accounting)',
                    'FK03': 'Display Vendor (Accounting)'
                }
                self.tcode_descriptions = demo_tcodes
                log_message(f"Created {len(self.tcode_descriptions)} sample transaction code descriptions for testing")
        except Exception as e:
            log_error(e, "Error loading transaction code descriptions")
        
        # Load event code descriptions
        try:
            events_file = PATHS.get("events_reference")
            if events_file and os.path.exists(events_file):
                df_events = pd.read_csv(events_file)
                self.event_descriptions = dict(zip(df_events["Event Code"], df_events["Event Code Description"]))
                log_message(f"Loaded {len(self.event_descriptions)} event code descriptions")
            else:
                # Create demo data for testing
                demo_events = {
                    'AU1': 'User Login',
                    'AUC': 'User Logout',
                    'AUE': 'User Logout (Explicit)',
                    'AU6': 'Session Manager Start',
                    'AUG': 'Session Manager Restart',
                    'BU': 'Record Created',
                    'BC': 'Record Changed',
                    'BD': 'Record Deleted',
                    'TX': 'Transaction Started'
                }
                self.event_descriptions = demo_events
                log_message(f"Created {len(self.event_descriptions)} sample event descriptions for testing")
        except Exception as e:
            log_error(e, "Error loading event descriptions")
        
        # Load table descriptions
        try:
            tables_file = PATHS.get("tables_reference")
            if tables_file and os.path.exists(tables_file):
                df_tables = pd.read_csv(tables_file)
                self.table_descriptions = dict(zip(df_tables["Table"], df_tables["Table Description"]))
                log_message(f"Loaded {len(self.table_descriptions)} table descriptions")
            else:
                # Create demo data for testing
                demo_tables = {
                    'MARA': 'General Material Data',
                    'MARC': 'Plant Material Data',
                    'KNA1': 'Customer Master (General Section)',
                    'LFA1': 'Vendor Master (General Section)',
                    'VBAK': 'Sales Document: Header Data',
                    'VBAP': 'Sales Document: Item Data',
                    'EKKO': 'Purchasing Document Header',
                    'EKPO': 'Purchasing Document Item',
                    'USR02': 'User Master Password Data',
                    'LIKP': 'Delivery Header'
                }
                self.table_descriptions = demo_tables
                log_message(f"Created {len(self.table_descriptions)} sample table descriptions for testing")
        except Exception as e:
            log_error(e, "Error loading table descriptions")
        
        # Load high-risk transaction codes
        try:
            high_risk_tcodes_file = PATHS.get("high_risk_tcodes")
            if high_risk_tcodes_file and os.path.exists(high_risk_tcodes_file):
                df_hr_tcodes = pd.read_csv(high_risk_tcodes_file)
                self.high_risk_tcodes = set(df_hr_tcodes["TCode"].str.upper())
                
                # Create category mapping if Category column exists
                if "Category" in df_hr_tcodes.columns:
                    self.high_risk_tcode_categories = dict(zip(df_hr_tcodes["TCode"].str.upper(), df_hr_tcodes["Category"]))
                
                log_message(f"Loaded {len(self.high_risk_tcodes)} high-risk transaction codes")
            else:
                # Create demo data for testing
                self.high_risk_tcodes = {'SE38', 'SE37', 'SE24', 'SE80', 'SU01', 'PFCG', 'SM30', 'SE16', 'SE16N', 'STMS'}
                self.high_risk_tcode_categories = {
                    'SE38': 'Development',
                    'SE37': 'Development',
                    'SE24': 'Development',
                    'SE80': 'Development',
                    'SU01': 'Security',
                    'PFCG': 'Security',
                    'SM30': 'Table Maintenance',
                    'SE16': 'Table Maintenance',
                    'SE16N': 'Table Maintenance',
                    'STMS': 'Transport'
                }
                log_message(f"Created {len(self.high_risk_tcodes)} sample high-risk transaction codes for testing")
        except Exception as e:
            log_error(e, "Error loading high-risk transaction codes")
        
        # Load high-risk tables
        try:
            high_risk_tables_file = PATHS.get("high_risk_tables")
            if high_risk_tables_file and os.path.exists(high_risk_tables_file):
                df_hr_tables = pd.read_csv(high_risk_tables_file)
                self.high_risk_tables = set(df_hr_tables["Table"].str.upper())
                
                # Create category mapping if Category column exists
                if "Category" in df_hr_tables.columns:
                    self.high_risk_table_categories = dict(zip(df_hr_tables["Table"].str.upper(), df_hr_tables["Category"]))
                
                log_message(f"Loaded {len(self.high_risk_tables)} high-risk tables")
            else:
                # Create demo data for testing
                self.high_risk_tables = {'USR02', 'USR01', 'USGRP', 'USOBT', 'AGR_USERS', 'AGR_DEFINE', 'USOBX_C', 'KNA1', 'LFA1'}
                self.high_risk_table_categories = {
                    'USR02': 'Security - User Password',
                    'USR01': 'Security - User Master',
                    'USGRP': 'Security - User Groups',
                    'USOBT': 'Security - Authorization Objects',
                    'AGR_USERS': 'Security - Role Assignments',
                    'AGR_DEFINE': 'Security - Role Definitions',
                    'USOBX_C': 'Security - Authorization Checks',
                    'KNA1': 'Master Data - Customer',
                    'LFA1': 'Master Data - Vendor'
                }
                log_message(f"Created {len(self.high_risk_tables)} sample high-risk tables for testing")
        except Exception as e:
            log_error(e, "Error loading high-risk tables")
    
    @handle_exception
    def analyze(self, session_data):
        """
        Enhance session data with additional analysis columns.
        
        Args:
            session_data: DataFrame containing session data with risk assessment
            
        Returns:
            Enhanced DataFrame with additional analysis columns
        """
        log_section("Enhancing Session Data with Additional Analysis")
        
        if session_data is None or session_data.empty:
            log_message("No session data provided for analysis", "ERROR")
            return pd.DataFrame()
        
        # Create a working copy to avoid SettingWithCopyWarning
        df = session_data.copy()
        
        # Add descriptive columns
        df = self._add_descriptive_columns(df)
        
        # Add analysis flag columns
        df = self._add_analysis_flag_columns(df)
        
        # Add observation and conclusion columns if they don't exist
        if "Observations" not in df.columns:
            df["Observations"] = ""
            
        if "Questions" not in df.columns:
            df["Questions"] = ""
            
        if "Response" not in df.columns:
            df["Response"] = ""
            
        if "Conclusion" not in df.columns:
            df["Conclusion"] = ""
            
        # Auto-populate conclusions for benign activities
        df = self._populate_conclusions_for_benign_activities(df)
        
        log_message(f"Enhanced analysis completed on {len(df)} records")
        return df
    
    def _add_descriptive_columns(self, df):
        """
        Add descriptive information columns.
        
        Args:
            df: DataFrame to enhance
            
        Returns:
            Enhanced DataFrame with descriptive columns
        """
        log_message("Adding descriptive columns for TCodes, Events, and Tables")
        
        # Add TCode description column - check for multiple possible TCode column names
        tcode_col = next((col for col in ['TCode', 'TCODE', 'SOURCE TA'] if col in df.columns), None)
        if tcode_col:
            df["TCode_Description"] = df[tcode_col].apply(
                lambda x: self.tcode_descriptions.get(x, "") if pd.notna(x) and x != "" else ""
            )
        else:
            df["TCode_Description"] = ""
        
        # Add Event description column - check for multiple possible Event column names
        event_col = next((col for col in ['Event', 'EVENT'] if col in df.columns), None)
        if event_col:
            df["Event_Description"] = df[event_col].apply(
                lambda x: self.event_descriptions.get(x, "") if pd.notna(x) and x != "" else ""
            )
        else:
            df["Event_Description"] = ""
        
        # Add Table description column - check for multiple possible Table column names
        table_col = next((col for col in ['Table', 'TABLE NAME', 'TABLE_NAME'] if col in df.columns), None)
        if table_col:
            df["Table_Description"] = df[table_col].apply(
                lambda x: self.table_descriptions.get(x, "") if pd.notna(x) and x != "" else ""
            )
        else:
            df["Table_Description"] = ""
            
        return df
    
    def _add_analysis_flag_columns(self, df):
        """
        Add analysis flag columns that identify specific risk categories.
        
        Args:
            df: DataFrame to enhance
            
        Returns:
            Enhanced DataFrame with analysis flag columns
        """
        log_message("Adding analysis flag columns")
        
        # Add Table Maintenance flag
        df["Table_Maintenance"] = self._identify_table_maintenance(df)
        
        # Add High Risk TCode flag
        df["High_Risk_TCode"] = self._identify_high_risk_tcodes(df)
        
        # Add Change Activity flag
        df["Change_Activity"] = self._identify_change_activity(df)
        
        # Add Transport Related Event flag
        df["Transport_Related_Event"] = self._identify_transport_events(df)
        
        # Add Debugging Related Event flag
        df["Debugging_Related_Event"] = self._identify_debugging_events(df)
        
        # Add Benign Activity flag
        df["Benign_Activity"] = self._identify_benign_activities(df)
        
        return df
    
    def _identify_table_maintenance(self, df):
        """
        Identify table maintenance activities.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with "Yes" for table maintenance activities, "" otherwise
        """
        # Initialize with empty strings
        table_maintenance = pd.Series("", index=df.index)
        
        # Check for table maintenance transaction codes
        table_maint_tcodes = ['SM30', 'SM31', 'SM34', 'SE16', 'SE16N', 'SM32', 'SE11', 'SE13']
        
        # Handle multiple possible column names
        tcode_col = next((col for col in ['TCode', 'TCODE', 'SOURCE TA'] if col in df.columns), None)
        if tcode_col:
            table_maintenance = table_maintenance.mask(
                df[tcode_col].fillna('').astype(str).isin(table_maint_tcodes), 
                "Yes"
            )
            
        # Check for table maintenance in risk description
        if "risk_description" in df.columns:
            table_maintenance = table_maintenance.mask(
                df["risk_description"].str.contains("table maintenance|modify table|database table|data dictionary", 
                                                   case=False, na=False, regex=True),
                "Yes"
            )
            
        # Look for direct table changes in the system logs
        if "Description" in df.columns:
            table_maintenance = table_maintenance.mask(
                df["Description"].str.contains("table|field", 
                                              case=False, na=False, regex=True) &
                df["Description"].str.contains("change|update|modify|create|delete|insert", 
                                              case=False, na=False, regex=True),
                "Yes"
            )
        
        # Look for table changes in the audit message
        msg_col = next((col for col in ['AUDIT LOG MSG. TEXT', 'MESSAGE', 'MSG'] if col in df.columns), None)
        if msg_col:
            table_maintenance = table_maintenance.mask(
                df[msg_col].fillna('').astype(str).str.contains("table|maintenance|field|data dictionary", 
                                                               case=False, regex=True),
                "Yes"
            )
            
        # Check for table-related activities in CDPOS
        if 'TABLE NAME' in df.columns:
            # Any operations on tables are considered table maintenance
            table_maintenance = table_maintenance.mask(
                (df['TABLE NAME'] != '') & df['TABLE NAME'].notna(),
                "Yes"
            )
            
        return table_maintenance
    
    def _identify_high_risk_tcodes(self, df):
        """
        Identify high-risk transaction codes.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with category name for high risk tcodes, "" otherwise
        """
        # Initialize with empty strings
        high_risk = pd.Series("", index=df.index)
        
        # Handle multiple possible column names
        tcode_col = next((col for col in ['TCode', 'TCODE', 'SOURCE TA'] if col in df.columns), None)
        
        if tcode_col and self.high_risk_tcodes:
            # Use categories if available, otherwise just "Yes"
            if self.high_risk_tcode_categories:
                for idx, row in df.iterrows():
                    tcode = str(row[tcode_col]).upper() if pd.notna(row[tcode_col]) else ""
                    if tcode and tcode in self.high_risk_tcode_categories:
                        high_risk.iloc[idx] = self.high_risk_tcode_categories[tcode]
            else:
                # Handle possible NaNs and convert to uppercase safely
                high_risk = high_risk.mask(
                    df[tcode_col].fillna('').astype(str).str.upper().isin([t.upper() for t in self.high_risk_tcodes]),
                    "Yes"
                )
        
        return high_risk
    
    def _identify_change_activity(self, df):
        """
        Identify change activities based on change indicators and other fields.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with change activity type or "" if not a change activity
        """
        # Initialize with empty strings
        change_activity = pd.Series("", index=df.index)
        
        # Check Change_Indicator column with multiple possible names
        indicator_col = next((col for col in ['Change_Indicator', 'CHANGE INDICATOR', 'CHANGE_INDICATOR'] 
                               if col in df.columns), None)
        
        if indicator_col:
            # Create mapping for common change indicators
            change_map = {
                "U": "02 - Update",  # Update
                "I": "01 - Insert",  # Insert
                "D": "06 - Delete",  # Delete
                "C": "04 - Create",  # Create
                "M": "02 - Update",  # Modify
            }
            
            # Apply mapping to change indicators
            for idx, row in df.iterrows():
                indicator = row[indicator_col] if pd.notna(row[indicator_col]) else ""
                indicator = str(indicator).upper() if indicator else ""
                
                if indicator in change_map:
                    change_activity.iloc[idx] = change_map[indicator]
        
        # Check Event column for change-related events with multiple possible names
        event_col = next((col for col in ['Event', 'EVENT'] if col in df.columns), None)
        
        if event_col:
            # These events indicate changes
            insert_events = ["BU", "BD", "BU1", "BU2", "BU3"]  # Record creation events
            update_events = ["BC", "BE", "BW", "BW1"]  # Record modification events
            delete_events = ["BD", "BD1", "BD2"]  # Record deletion events
            
            # Mark change activities based on event codes
            change_activity = change_activity.mask(
                (change_activity == "") & df[event_col].isin(insert_events), 
                "01 - Insert"
            )
            change_activity = change_activity.mask(
                (change_activity == "") & df[event_col].isin(update_events), 
                "02 - Update"
            )
            change_activity = change_activity.mask(
                (change_activity == "") & df[event_col].isin(delete_events), 
                "06 - Delete"
            )
        
        # Check risk_description for change indicators
        if "risk_description" in df.columns:
            # Look for insert-related terms in risk description
            change_activity = change_activity.mask(
                (change_activity == "") & df["risk_description"].str.contains(
                    r"insert|create|new|add", case=False, na=False, regex=True
                ),
                "01 - Insert"
            )
            
            # Look for update-related terms in risk description
            change_activity = change_activity.mask(
                (change_activity == "") & df["risk_description"].str.contains(
                    r"update|modif|change", case=False, na=False, regex=True
                ),
                "02 - Update"
            )
            
            # Look for delete-related terms in risk description
            change_activity = change_activity.mask(
                (change_activity == "") & df["risk_description"].str.contains(
                    r"delete|remov", case=False, na=False, regex=True
                ), 
                "06 - Delete"
            )
        
        # Check message text for change indicators
        msg_col = next((col for col in ['AUDIT LOG MSG. TEXT', 'MESSAGE', 'MSG'] if col in df.columns), None)
        if msg_col:
            # Look for insert-related terms
            change_activity = change_activity.mask(
                (change_activity == "") & df[msg_col].fillna('').astype(str).str.contains(
                    r"insert|create|new|add", case=False, regex=True
                ),
                "01 - Insert"
            )
            
            # Look for update-related terms
            change_activity = change_activity.mask(
                (change_activity == "") & df[msg_col].fillna('').astype(str).str.contains(
                    r"update|modif|change", case=False, regex=True
                ),
                "02 - Update"
            )
            
            # Look for delete-related terms
            change_activity = change_activity.mask(
                (change_activity == "") & df[msg_col].fillna('').astype(str).str.contains(
                    r"delete|remov", case=False, regex=True
                ), 
                "06 - Delete"
            )
        
        # Check for change values in CDPOS data
        if 'NEW VALUE' in df.columns and 'OLD VALUE' in df.columns:
            # If there's a new value and no old value, it's an insert
            change_activity = change_activity.mask(
                (change_activity == "") & 
                (df['NEW VALUE'].notna()) & (df['NEW VALUE'] != '') & 
                ((df['OLD VALUE'].isna()) | (df['OLD VALUE'] == '')),
                "01 - Insert"
            )
            
            # If there's an old value and a new value, it's an update
            change_activity = change_activity.mask(
                (change_activity == "") & 
                (df['NEW VALUE'].notna()) & (df['NEW VALUE'] != '') & 
                (df['OLD VALUE'].notna()) & (df['OLD VALUE'] != ''),
                "02 - Update"
            )
            
            # If there's an old value and no new value, it's a delete
            change_activity = change_activity.mask(
                (change_activity == "") & 
                ((df['NEW VALUE'].isna()) | (df['NEW VALUE'] == '')) & 
                (df['OLD VALUE'].notna()) & (df['OLD VALUE'] != ''),
                "06 - Delete"
            )
        
        # Check source column for CDPOS/CDHDR data
        if 'Source' in df.columns:
            # CDHDR and CDPOS both represent change documents
            change_activity = change_activity.mask(
                (change_activity == "") & 
                df['Source'].isin(['CDHDR', 'CDPOS']),
                "02 - Update"
            )
            
        return change_activity
    
    def _identify_transport_events(self, df):
        """
        Identify transport-related events.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with "Yes" for transport events, "" otherwise
        """
        # Initialize with empty strings
        transport_related = pd.Series("", index=df.index)
        
        # Check for transport-related transaction codes
        transport_tcodes = ['STMS', 'SE01', 'SE09', 'SE10', 'SE03', 'SE38', 'SE80']
        
        if "TCode" in df.columns:
            transport_related = transport_related.mask(
                df["TCode"].isin(transport_tcodes), 
                "Yes"
            )
        
        # Check for transport-related terms in risk description
        if "risk_description" in df.columns:
            transport_related = transport_related.mask(
                df["risk_description"].str.contains(
                    "transport|release|import|STMS|development|request|package|TR", 
                    case=False, na=False, regex=True
                ),
                "Yes"
            )
        
        # Check for transport-related events
        if "Event" in df.columns:
            transport_events = ['EU1', 'EU2', 'EU3', 'EU4', 'CL', 'CT']  # Transport-related event codes
            transport_related = transport_related.mask(
                df["Event"].isin(transport_events), 
                "Yes"
            )
        
        # Check for transport-related keywords in Description
        if "Description" in df.columns:
            transport_related = transport_related.mask(
                df["Description"].str.contains(
                    "transport|release|import|STMS|development|request|package|workbench|TR", 
                    case=False, na=False, regex=True
                ),
                "Yes"
            )
            
        return transport_related
    
    def _identify_debugging_events(self, df):
        """
        Identify debugging-related events.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with "Yes" for debugging events, "" otherwise
        """
        # Initialize with empty strings
        debugging_related = pd.Series("", index=df.index)
        
        # Check for debugging transaction codes
        debug_tcodes = ['/H', 'ABAPDBG', 'SE24', 'SE37', 'SE38', 'SE80']
        
        # Handle multiple possible column names
        tcode_col = next((col for col in ['TCode', 'TCODE', 'SOURCE TA'] if col in df.columns), None)
        if tcode_col:
            debugging_related = debugging_related.mask(
                df[tcode_col].fillna('').astype(str).isin(debug_tcodes), 
                "Yes"
            )
        
        # Check for debugging-related terms in risk description
        if "risk_description" in df.columns:
            debugging_related = debugging_related.mask(
                df["risk_description"].str.contains(
                    "debug|breakpoint|code inspection|trace|ABAP|function module", 
                    case=False, na=False, regex=True
                ),
                "Yes"
            )
        
        # Check for debugging-related events
        event_col = next((col for col in ['Event', 'EVENT'] if col in df.columns), None)
        if event_col:
            debug_events = ['DB', 'DB1', 'DB2', 'DB3', 'DBC', 'DBG', 'DBI']  # Debug-related event codes
            debugging_related = debugging_related.mask(
                df[event_col].isin(debug_events), 
                "Yes"
            )
        
        # Check for debugging keywords in Description or message
        for col_name in ['Description', 'AUDIT LOG MSG. TEXT', 'MESSAGE', 'MSG']:
            if col_name in df.columns:
                debugging_related = debugging_related.mask(
                    df[col_name].fillna('').astype(str).str.contains(
                        "debug|breakpoint|trace|ABAP|development|function module", 
                        case=False, regex=True
                    ),
                    "Yes"
                )
        
        # Check for debug markers in variables
        for col_name in ['VARIABLE 1', 'VARIABLE 2', 'VARIABLE', 'VAR', 'NOTE']:
            if col_name in df.columns:
                debugging_related = debugging_related.mask(
                    df[col_name].fillna('').astype(str).str.contains(
                        "DEBUG|D!DEBUG|BREAK|TRACE", 
                        case=False, regex=True
                    ),
                    "Yes"
                )
            
        return debugging_related
    
    def _identify_benign_activities(self, df):
        """
        Identify benign activities like display, logon/logoff, etc.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Series with activity type for benign activities, "" otherwise
        """
        # Initialize with empty strings
        benign_activity = pd.Series("", index=df.index)
        
        # Check for login/logout events
        event_col = next((col for col in ['Event', 'EVENT'] if col in df.columns), None)
        if event_col:
            # Login events
            benign_activity = benign_activity.mask(
                df[event_col].isin(['AU1']), 
                "Logon"
            )
            
            # Logout events
            benign_activity = benign_activity.mask(
                df[event_col].isin(['AUC', 'AUE']), 
                "Logoff"
            )
            
            # Session manager events
            benign_activity = benign_activity.mask(
                df[event_col].isin(['AU6', 'AUG']), 
                "Session Manager"
            )
        
        # Check for display transactions
        tcode_col = next((col for col in ['TCode', 'TCODE', 'SOURCE TA'] if col in df.columns), None)
        if tcode_col:
            # Define display transaction patterns
            display_tcodes = ['VA03', 'MM03', 'ME23', 'FK03', 'BP03', 'XD01', 'XD02', 'XD03', 'FD03', 'IW33']
            tcode_starts_with_display = df[tcode_col].fillna('').astype(str).str.endswith('03')  # Many display transactions end with 03
            
            # Identify display activities (read-only)
            benign_activity = benign_activity.mask(
                (benign_activity == "") & 
                ((df[tcode_col].fillna('').astype(str).isin(display_tcodes)) | tcode_starts_with_display) &
                ~df[tcode_col].fillna('').astype(str).str.upper().isin([t.upper() for t in self.high_risk_tcodes]),
                "Display"
            )
        
        # Check risk level for low risk activities
        if "risk_level" in df.columns:
            benign_activity = benign_activity.mask(
                (benign_activity == "") & 
                (df["risk_level"] == "Low") & 
                ~(df["Change_Activity"].str.len() > 0) &  # No change activity
                ~(df["High_Risk_TCode"].str.len() > 0) &  # Not a high-risk transaction
                ~(df["Table_Maintenance"].str.len() > 0),  # Not table maintenance
                "Low Risk"
            )
        
        # Check for display terms in message text
        msg_col = next((col for col in ['AUDIT LOG MSG. TEXT', 'MESSAGE', 'MSG'] if col in df.columns), None)
        if msg_col:
            benign_activity = benign_activity.mask(
                (benign_activity == "") & 
                df[msg_col].fillna('').astype(str).str.contains(
                    "display|view|show|read|query|report", 
                    case=False, regex=True
                ) &
                ~df[msg_col].fillna('').astype(str).str.contains(
                    "change|update|modify|create|delete|sensitive|critical|high risk", 
                    case=False, regex=True
                ),
                "Display"
            )
        
        # Further check risk description for display indicators
        if "risk_description" in df.columns:
            benign_activity = benign_activity.mask(
                (benign_activity == "") & 
                df["risk_description"].str.contains(
                    "view|display|information viewing|standard system usage|read-only", 
                    case=False, na=False, regex=True
                ) &
                ~df["risk_description"].str.contains(
                    "sensitive|critical|high risk|unusual|suspicious", 
                    case=False, na=False, regex=True
                ),
                "Display"
            )
        
        return benign_activity
    
    def _populate_conclusions_for_benign_activities(self, df):
        """
        Auto-populate conclusions for benign activities based on SysAid ticket.
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with populated conclusions
        """
        log_message("Auto-populating conclusions for benign activities")
        
        # Check if the Benign_Activity and SYSAID # columns exist
        if "Benign_Activity" not in df.columns or "SYSAID #" not in df.columns:
            return df
        
        # Create mask for benign activities with a SysAid ticket
        benign_mask = (df["Benign_Activity"].str.len() > 0) & (df["SYSAID #"].notna()) & (df["SYSAID #"] != "") & (df["Conclusion"] == "")
        
        # Count records to be populated
        benign_count = benign_mask.sum()
        if benign_count > 0:
            log_message(f"Auto-populating conclusions for {benign_count} benign activities with SysAid tickets")
            
            # Update conclusions
            df.loc[benign_mask, "Conclusion"] = df.loc[benign_mask, "Benign_Activity"].apply(
                lambda x: f"Activity appears to be appropriate based on SysAid ticket ({x} activity)"
            )
        
        return df


if __name__ == "__main__":
    """
    Simple test if run as main script.
    """
    print("SAP Audit Enhanced Analysis Module")
    print("Run with a session DataFrame to perform additional analysis.")
    print("Example:")
    print("  from sap_audit_analyzer import SAPAuditAnalyzer")
    print("  analyzer = SAPAuditAnalyzer()")
    print("  enhanced_df = analyzer.analyze(session_df)")
