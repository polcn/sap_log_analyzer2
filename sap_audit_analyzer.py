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
                log_message("Transaction code reference file not found. TCode descriptions will not be available.", "WARNING")
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
                log_message("Event code reference file not found. Event descriptions will not be available.", "WARNING")
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
                log_message("Table reference file not found. Table descriptions will not be available.", "WARNING")
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
                log_message("High-risk transaction codes reference file not found. High-risk TCode flagging will not be available.", "WARNING")
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
                log_message("High-risk tables reference file not found. High-risk table flagging will not be available.", "WARNING")
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
        
        # Add TCode description column
        if "TCode" in df.columns:
            df["TCode_Description"] = df["TCode"].apply(
                lambda x: self.tcode_descriptions.get(x, "") if pd.notna(x) else ""
            )
        
        # Add Event description column
        if "Event" in df.columns:
            df["Event_Description"] = df["Event"].apply(
                lambda x: self.event_descriptions.get(x, "") if pd.notna(x) else ""
            )
        
        # Add Table description column
        if "Table" in df.columns:
            df["Table_Description"] = df["Table"].apply(
                lambda x: self.table_descriptions.get(x, "") if pd.notna(x) else ""
            )
            
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
        
        if "TCode" in df.columns:
            table_maintenance = table_maintenance.mask(
                df["TCode"].isin(table_maint_tcodes), 
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
        
        if "TCode" in df.columns and self.high_risk_tcodes:
            # Use categories if available, otherwise just "Yes"
            if self.high_risk_tcode_categories:
                for idx, row in df.iterrows():
                    tcode = row["TCode"].upper() if pd.notna(row["TCode"]) else ""
                    if tcode in self.high_risk_tcode_categories:
                        high_risk.iloc[idx] = self.high_risk_tcode_categories[tcode]
            else:
                high_risk = high_risk.mask(
                    df["TCode"].str.upper().isin([t.upper() for t in self.high_risk_tcodes]),
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
        
        # Check Change_Indicator column
        if "Change_Indicator" in df.columns:
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
                indicator = row["Change_Indicator"] if pd.notna(row["Change_Indicator"]) else ""
                indicator = indicator.upper() if isinstance(indicator, str) else ""
                
                if indicator in change_map:
                    change_activity.iloc[idx] = change_map[indicator]
        
        # Check Event column for change-related events
        if "Event" in df.columns:
            # These events indicate changes
            insert_events = ["BU", "BD", "BU1", "BU2", "BU3"]  # Record creation events
            update_events = ["BC", "BE", "BW", "BW1"]  # Record modification events
            delete_events = ["BD", "BD1", "BD2"]  # Record deletion events
            
            # Mark change activities based on event codes
            change_activity = change_activity.mask(
                (change_activity == "") & df["Event"].isin(insert_events), 
                "01 - Insert"
            )
            change_activity = change_activity.mask(
                (change_activity == "") & df["Event"].isin(update_events), 
                "02 - Update"
            )
            change_activity = change_activity.mask(
                (change_activity == "") & df["Event"].isin(delete_events), 
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
        
        if "TCode" in df.columns:
            debugging_related = debugging_related.mask(
                df["TCode"].isin(debug_tcodes), 
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
        if "Event" in df.columns:
            debug_events = ['DB', 'DB1', 'DB2', 'DB3', 'DBC', 'DBG', 'DBI']  # Debug-related event codes
            debugging_related = debugging_related.mask(
                df["Event"].isin(debug_events), 
                "Yes"
            )
        
        # Check for debugging keywords in Description
        if "Description" in df.columns:
            debugging_related = debugging_related.mask(
                df["Description"].str.contains(
                    "debug|breakpoint|trace|ABAP|development|function module", 
                    case=False, na=False, regex=True
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
        if "Event" in df.columns:
            # Login events
            benign_activity = benign_activity.mask(
                df["Event"].isin(['AU1']), 
                "Logon"
            )
            
            # Logout events
            benign_activity = benign_activity.mask(
                df["Event"].isin(['AUC', 'AUE']), 
                "Logoff"
            )
            
            # Session manager events
            benign_activity = benign_activity.mask(
                df["Event"].isin(['AU6', 'AUG']), 
                "Session Manager"
            )
        
        # Check for display transactions (risk level usually low)
        if "risk_level" in df.columns and "TCode" in df.columns:
            tcode_starts_with_display = df["TCode"].astype(str).str.startswith(('F', 'S', 'MB', 'MM', 'VA', 'VL', 'XD'))
            
            # Identify display activities (read-only)
            benign_activity = benign_activity.mask(
                (benign_activity == "") & 
                (df["risk_level"] == "Low") & 
                ~df["TCode"].isin(self.high_risk_tcodes) &
                ~(df["Change_Activity"].str.len() > 0),  # No change activity
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
