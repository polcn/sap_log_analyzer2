#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Output Generation Module

This module provides functionality for generating formatted unified output reports from SAP audit data.
It implements a single main tab approach that combines SM20, CDHDR, and CDPOS data into a unified view
with additional analysis columns for audit workflow.

Key features:
- Single main tab with unified view of audit data
- Enhanced analysis flag columns for better categorization
- Color-coded headers for different column types
- Automated conclusions for standard activities
- Eviden-specific columns with distinct formatting
"""

import os
import pandas as pd
import json
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
import matplotlib.pyplot as plt
from io import BytesIO
from typing import Dict, List, Any, Optional, Union, Tuple

# Import configuration and utilities
from sap_audit_config import PATHS, REPORTING, COLUMNS, SETTINGS, RISK
from sap_audit_utils import (
    log_message, log_section, log_error, handle_exception,
    clean_whitespace, validate_required_columns
)

# Import record counter if available
try:
    from sap_audit_record_counts import record_counter
except ImportError:
    # Placeholder if record counter is not available
    class RecordCounter:
        def update_source_counts(self, source_type, file_name, original_count, final_count):
            pass
        def update_timeline_count(self, total_records, source_counts=None):
            pass
        def get_counts_for_report(self):
            return {"completeness_score": 0, "source_files": []}
    record_counter = RecordCounter()

# Constants for risk level colors
RISK_COLORS = {
    "Critical": "#7030A0",  # Purple for Critical
    "High": "#FFC7CE",      # Red/Pink for High
    "Medium": "#FFEB9C",    # Yellow for Medium
    "Low": "#C6EFCE",       # Green for Low
}

# Constants for data source column colors
SOURCE_COLORS = {
    "SM20": "#FFD966",      # Yellow for SM20
    "CDHDR": "#9BC2E6",     # Blue for CDHDR
    "CDPOS": "#C6E0B4",     # Green for CDPOS
    "Generated": "#F4B084", # Orange for generated fields
    "SysAid": "#D9D2E9",    # Light Purple for SysAid
    "Eviden": "#CCFFCC",    # Light Green for Eviden columns
    "Analysis": "#FFCC99",  # Peach for analysis columns
}


class OutputGenerator(ABC):
    """
    Abstract base class for output generation using the Template Method pattern.
    
    This class provides the structure for generating formatted output reports from
    SAP audit data. It defines the template method (generate_report) and abstract
    methods that subclasses must implement for different output formats.
    """
    
    def __init__(self, config=None):
        """
        Initialize with optional custom configuration.
        
        Args:
            config: Dictionary with configuration overrides
        """
        self.config = config or REPORTING
        self.paths = PATHS
        self.default_output_path = self.paths.get("audit_report")
        self.column_mapping = self._initialize_column_mapping()
    
    def _initialize_column_mapping(self) -> Dict[str, str]:
        """
        Initialize column mapping for source attribution.
        
        Returns:
            Dict mapping columns to their source systems
        """
        # Default column mappings from configuration
        column_sources = {
            # SM20 columns
            'SM20_Datetime': 'SM20',
            'SOURCE TA': 'SM20',
            'AUDIT LOG MSG. TEXT': 'SM20',
            'Variable_First': 'SM20',
            'Variable_2': 'SM20',
            'Variable_Data': 'SM20',
            'Description': 'SM20',
            
            # CDHDR columns
            'Change_Timestamp': 'CDHDR',
            'TCode_CD': 'CDHDR',
            'USER': 'CDHDR',
            'DOC.NUMBER': 'CDHDR',
            'OBJECT': 'CDHDR',
            'OBJECT VALUE': 'CDHDR',
            'Object': 'CDHDR',
            'Object_ID': 'CDHDR',
            'Doc_Number': 'CDHDR',
            
            # CDPOS columns
            'Table_Name': 'CDPOS',
            'FIELD NAME': 'CDPOS',
            'Change_Indicator': 'CDPOS',
            'NEW VALUE': 'CDPOS',
            'OLD VALUE': 'CDPOS',
            'Table': 'CDPOS',
            'Field': 'CDPOS',
            'Old_Value': 'CDPOS',
            'New_Value': 'CDPOS',
            
            # Generated columns
            'risk_level': 'Generated',
            'risk_description': 'Generated',
            'risk_factors': 'Generated',
            'sap_risk_level': 'Generated',
            'Session ID with Date': 'Generated',
            'User': 'Generated',
            'Datetime': 'Generated',
            'Source': 'Generated',
            'TCode': 'Generated',
            'TCode_Description': 'Generated',
            'Event_Description': 'Generated',
            'Table_Description': 'Generated',
            
            # SysAid columns
            'SYSAID#': 'SysAid',
            'SYSAID #': 'SysAid',
            'Title': 'SysAid',
            'SysAid Description': 'SysAid',
            'Notes': 'SysAid',
            'Request user': 'SysAid',
            'Process manager': 'SysAid',
            'Request time': 'SysAid',
            'SysAid Title': 'SysAid',
            'SysAid Notes': 'SysAid',
            'SysAid Request User': 'SysAid',
            
            # Analysis columns (new)
            'Table_Maintenance': 'Analysis',
            'High_Risk_TCode': 'Analysis',
            'Change_Activity': 'Analysis',
            'Transport_Related_Event': 'Analysis',
            'Debugging_Related_Event': 'Analysis',
            'Benign_Activity': 'Analysis',
            'Observations': 'Analysis',
            'Questions': 'Analysis',
            'Conclusion': 'Analysis',
            
            # Eviden columns (new)
            'Response': 'Eviden'
        }
        
        # Add any custom mappings from config
        custom_mappings = self.config.get("column_source_mappings", {})
        column_sources.update(custom_mappings)
        
        return column_sources
    
    def generate_report(self, session_data, output_path=None):
        """
        Template method for generating output reports.
        
        This method defines the skeleton of the report generation algorithm,
        deferring some steps to subclasses. The steps are:
        1. Validate input data
        2. Prepare data for reporting
        3. Generate statistics
        4. Create the output file
        
        Args:
            session_data: DataFrame with session timeline
            output_path: Optional path override for output file
            
        Returns:
            bool: Success status
        """
        log_section(f"Generating {self.__class__.__name__.replace('OutputGenerator', '')} Report")
        
        # Set the output path
        output_path = output_path or self.default_output_path
        log_message(f"Output will be saved to: {output_path}")
        
        try:
            # Step 1: Validate input data
            if not self._validate_input(session_data):
                return False
            
            # Step 2: Prepare data for reporting
            prepared_data = self._prepare_report_data(session_data)
            
            # Step 3: Generate summary statistics
            statistics = self._generate_statistics(prepared_data)
            
            # Step 4: Create and format output file
            success = self._create_output_file(prepared_data, statistics, output_path)
            
            if success:
                log_message(f"Report generation completed successfully: {output_path}")
            else:
                log_message("Report generation failed", "ERROR")
            
            return success
            
        except Exception as e:
            log_error(e, "Error generating report")
            return False
    
    def _validate_input(self, data) -> bool:
        """
        Validate the input data.
        
        Args:
            data: The session data to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if data is None:
            log_message("No data provided for report generation", "ERROR")
            return False
        
        if len(data) == 0:
            log_message("Empty dataset provided for report generation", "WARNING")
            return False
        
        # Check for required columns
        required_cols = self.config.get("required_columns", ["Session ID", "User", "Datetime"])
        missing = [col for col in required_cols if col not in data.columns]
        
        if missing:
            log_message(f"Missing required columns: {', '.join(missing)}", "WARNING")
            # Continue anyway, but warn the user
        
        return True
    
    def _prepare_report_data(self, data) -> pd.DataFrame:
        """
        Prepare data for reporting by cleaning, filtering, and organizing.
        This method also adds any required analysis columns that don't already exist.
        
        Args:
            data: The raw session data
            
        Returns:
            DataFrame: Cleaned and prepared data
        """
        # Create a copy to avoid modifying the original
        prepared_data = data.copy()
        
        # Clean up data - replace NaN values with empty strings
        prepared_data = clean_whitespace(prepared_data)
        prepared_data = prepared_data.fillna('')
        
        # Convert all values to strings
        for col in prepared_data.columns:
            try:
                prepared_data[col] = prepared_data[col].astype(str)
                prepared_data[col] = prepared_data[col].replace('nan', '').replace('None', '')
            except Exception as e:
                log_message(f"Warning: Could not convert column '{col}' to string: {str(e)}", "WARNING")
        
        # Add analysis flag columns if they don't exist
        prepared_data = self._add_analysis_flag_columns(prepared_data)
        
        # Add audit workflow columns if they don't exist
        prepared_data = self._add_audit_workflow_columns(prepared_data)
        
        # Auto-populate conclusions for standard activities
        prepared_data = self._auto_populate_conclusions(prepared_data)
        
        # Organize columns according to configuration if specified
        if "column_order" in self.config:
            ordered_cols = [col for col in self.config["column_order"] if col in prepared_data.columns]
            remaining_cols = [col for col in prepared_data.columns if col not in ordered_cols]
            prepared_data = prepared_data[ordered_cols + remaining_cols]
        
        log_message(f"Prepared {len(prepared_data)} records for reporting")
        return prepared_data
    
    def _add_analysis_flag_columns(self, data):
        """
        Add analysis flag columns if they don't already exist.
        
        Args:
            data: DataFrame to enhance
            
        Returns:
            DataFrame with analysis flag columns
        """
        # Initialize new columns if they don't exist
        flag_columns = [
            'Table_Maintenance', 'High_Risk_TCode', 'Change_Activity',
            'Transport_Related_Event', 'Debugging_Related_Event', 'Benign_Activity'
        ]
        
        # Only add columns that don't already exist
        for col in flag_columns:
            if col not in data.columns:
                data[col] = ""
        
        # If data has already been processed by the analyzer, we don't need to add logic
        # Otherwise, add basic logic for each column
        
        # Table Maintenance flag
        if 'Table_Maintenance' in data.columns and data['Table_Maintenance'].astype(str).eq('').all():
            log_message("Adding Table Maintenance flag logic")
            # Check for table maintenance transaction codes
            table_maint_tcodes = ['SM30', 'SM31', 'SM34', 'SE16', 'SE16N', 'SM32', 'SE11', 'SE13']
            
            if "TCode" in data.columns:
                data.loc[data["TCode"].isin(table_maint_tcodes), "Table_Maintenance"] = "Yes"
            
        # High Risk TCode flag - basic version, could be expanded later
        if 'High_Risk_TCode' in data.columns and data['High_Risk_TCode'].astype(str).eq('').all():
            log_message("Adding High Risk TCode flag logic")
            high_risk_tcodes = [
                # Development
                'SE38', 'SE37', 'SE80', 'SE24', 'SE93',
                # Security
                'SU01', 'PFCG', 'SU53', 'SU10', 'SU24',
                # Table maintenance
                'SM30', 'SM31', 'SE16', 'SE16N', 'SE11',
                # Configuration
                'SPRO', 'SCOT', 'SMLG',
                # Transport
                'STMS', 'SE01', 'SE09', 'SE10'
            ]
            
            # Categorize high risk TCodes
            tcode_categories = {
                'Development': ['SE38', 'SE37', 'SE80', 'SE24', 'SE93'],
                'Security': ['SU01', 'PFCG', 'SU53', 'SU10', 'SU24'],
                'Table Maintenance': ['SM30', 'SM31', 'SE16', 'SE16N', 'SE11'],
                'Configuration': ['SPRO', 'SCOT', 'SMLG'],
                'Transport': ['STMS', 'SE01', 'SE09', 'SE10']
            }
            
            if "TCode" in data.columns:
                for category, tcodes in tcode_categories.items():
                    data.loc[data["TCode"].isin(tcodes), "High_Risk_TCode"] = category
        
        # Change Activity flag
        if 'Change_Activity' in data.columns and data['Change_Activity'].astype(str).eq('').all():
            log_message("Adding Change Activity flag logic")
            
            if "Change_Indicator" in data.columns:
                # Map common change indicators
                change_map = {
                    "U": "02 - Update",  # Update
                    "I": "01 - Insert",  # Insert
                    "D": "06 - Delete",  # Delete
                    "C": "04 - Create",  # Create
                    "M": "02 - Update",  # Modify
                }
                
                # First normalize the change indicators
                data["_temp_change_ind"] = data["Change_Indicator"].str.strip().str.upper()
                
                # Apply the mapping
                for indicator, activity in change_map.items():
                    data.loc[data["_temp_change_ind"] == indicator, "Change_Activity"] = activity
                
                # Drop the temporary column
                data = data.drop(columns=["_temp_change_ind"])
            
            # Handle display TCodes specifically
            if "TCode" in data.columns:
                display_tcodes = [tcode for tcode in data["TCode"].unique() 
                                 if str(tcode).endswith('03') or str(tcode).endswith('04')]
                # Don't mark display transactions as change activity unless they already have a change indicator
                data.loc[(data["TCode"].isin(display_tcodes)) & 
                        (data["Change_Activity"] == ""), "Change_Activity"] = ""
        
        # Transport Related Event flag
        if 'Transport_Related_Event' in data.columns and data['Transport_Related_Event'].astype(str).eq('').all():
            log_message("Adding Transport Related Event flag logic")
            
            # Transport-related transaction codes
            transport_tcodes = ['STMS', 'SE01', 'SE09', 'SE10', 'SE03', 'SE38', 'SE80']
            
            if "TCode" in data.columns:
                data.loc[data["TCode"].isin(transport_tcodes), "Transport_Related_Event"] = "Yes"
            
            # Check for transport-related terms in description if available
            if "Description" in data.columns:
                transport_terms = ['transport', 'release', 'import', 'STMS', 'development', 
                                  'request', 'package', 'workbench', 'TR']
                
                # Create a regex pattern for transport terms
                transport_pattern = '|'.join(transport_terms)
                
                # Flag rows with transport terms in description
                data.loc[(data["Transport_Related_Event"] == "") & 
                         (data["Description"].str.contains(transport_pattern, case=False, na=False)), 
                         "Transport_Related_Event"] = "Yes"
        
        # Debugging Related Event flag
        if 'Debugging_Related_Event' in data.columns and data['Debugging_Related_Event'].astype(str).eq('').all():
            log_message("Adding Debugging Related Event flag logic")
            
            # Debug transaction codes
            debug_tcodes = ['/H', 'ABAPDBG', 'SE24', 'SE37', 'SE38', 'SE80']
            
            if "TCode" in data.columns:
                data.loc[data["TCode"].isin(debug_tcodes), "Debugging_Related_Event"] = "Yes"
            
            # Check for debug markers in Variable_2 if available
            if "Variable_2" in data.columns:
                data.loc[data["Variable_2"].str.contains('I!|D!|G!', na=False), 
                         "Debugging_Related_Event"] = "Yes"
            
            # Look for debug terms in description
            if "Description" in data.columns:
                debug_terms = ['debug', 'breakpoint', 'trace', 'ABAP', 'function module']
                debug_pattern = '|'.join(debug_terms)
                
                data.loc[(data["Debugging_Related_Event"] == "") & 
                         (data["Description"].str.contains(debug_pattern, case=False, na=False)), 
                         "Debugging_Related_Event"] = "Yes"
        
        # Benign Activity flag
        if 'Benign_Activity' in data.columns and data['Benign_Activity'].astype(str).eq('').all():
            log_message("Adding Benign Activity flag logic")
            
            # Check for logon/logoff events
            if "Event" in data.columns:
                # Logon events
                data.loc[data["Event"].isin(['AU1']), "Benign_Activity"] = "Logon"
                
                # Logoff events
                data.loc[data["Event"].isin(['AUC', 'AUE']), "Benign_Activity"] = "Logoff"
                
                # Session manager events
                data.loc[data["Event"].isin(['AU6', 'AUG']), "Benign_Activity"] = "Session Manager"
            
            # Identify display TCodes if risk_level is Low and no other flags are set
            if "TCode" in data.columns:
                # Look for display TCodes (typically end with 03)
                display_tcodes = [tcode for tcode in data["TCode"].unique() 
                                 if str(tcode).endswith('03') or str(tcode).endswith('04')]
                
                # Only flag as Display if:
                # - TCode is a display TCode
                # - Not already categorized as something else
                # - Not a debugging event (as per user's requirement)
                data.loc[(data["TCode"].isin(display_tcodes)) & 
                         (data["Benign_Activity"] == "") &
                         (data["Debugging_Related_Event"] != "Yes") &
                         (data["Change_Activity"] == ""), "Benign_Activity"] = "Display"
        
        return data
    
    def _add_audit_workflow_columns(self, data):
        """
        Add audit workflow columns if they don't already exist.
        
        Args:
            data: DataFrame to enhance
            
        Returns:
            DataFrame with audit workflow columns
        """
        # Initialize workflow columns if they don't exist
        workflow_columns = ['Observations', 'Questions', 'Response', 'Conclusion']
        
        for col in workflow_columns:
            if col not in data.columns:
                data[col] = ""
        
        return data
    
    def _auto_populate_conclusions(self, data):
        """
        Auto-populate conclusions for standard activities based on business rules.
        
        Args:
            data: DataFrame to enhance
            
        Returns:
            DataFrame with populated conclusions
        """
        log_message("Auto-populating conclusions for standard activities")
        
        # Only populate empty conclusions
        conclusion_mask = data["Conclusion"] == ""
        
        # Rule 1: Benign activity with SysAid ticket
        if "Benign_Activity" in data.columns and "SYSAID #" in data.columns:
            benign_mask = (data["Benign_Activity"] != "") & (data["SYSAID #"] != "") & conclusion_mask
            data.loc[benign_mask, "Conclusion"] = data.loc[benign_mask, "Benign_Activity"].apply(
                lambda x: f"Activity appears to be appropriate based on SysAid ticket ({x} activity)"
            )
        
        # Rule 2: Display activity with no changes
        display_mask = (data["Benign_Activity"] == "Display") & (data["Change_Activity"] == "") & conclusion_mask
        data.loc[display_mask, "Conclusion"] = "Display activity - no changes detected"
        
        # Rule 3: Standard session management (logon, logoff, session manager)
        session_mask = data["Benign_Activity"].isin(["Logon", "Logoff", "Session Manager"]) & conclusion_mask
        data.loc[session_mask, "Conclusion"] = "Standard session management activity"
        
        # Count populated conclusions
        populated_count = (~conclusion_mask).sum() - (~data["Conclusion"].eq("")).sum()
        log_message(f"Auto-populated {populated_count} conclusions")
        
        return data
    
    def _generate_statistics(self, data) -> Dict[str, Any]:
        """
        Generate summary statistics from the data.
        
        Args:
            data: The prepared session data
            
        Returns:
            Dict: Statistics for the report
        """
        stats = {
            "record_count": len(data),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Record session statistics if session column exists
        if "Session ID" in data.columns:
            stats["session_count"] = data["Session ID"].nunique()
        elif "Session ID with Date" in data.columns:
            stats["session_count"] = data["Session ID with Date"].nunique()
        else:
            stats["session_count"] = 0
        
        # Record user statistics if user column exists
        if "User" in data.columns:
            stats["user_count"] = data["User"].nunique()
        else:
            stats["user_count"] = 0
        
        # Calculate risk level statistics if risk_level column exists
        if "risk_level" in data.columns:
            risk_counts = data["risk_level"].value_counts().to_dict()
            risk_stats = {
                "Critical": int(risk_counts.get("Critical", 0)),
                "High": int(risk_counts.get("High", 0)),
                "Medium": int(risk_counts.get("Medium", 0)),
                "Low": int(risk_counts.get("Low", 0))
            }
            
            # Calculate percentages
            total = sum(risk_stats.values())
            if total > 0:
                risk_pct = {k: (v / total) * 100 for k, v in risk_stats.items()}
            else:
                risk_pct = {k: 0 for k in risk_stats.keys()}
            
            stats["risk_counts"] = risk_stats
            stats["risk_percentages"] = risk_pct
        
        # Calculate statistics on analysis flags
        if "Table_Maintenance" in data.columns:
            stats["table_maintenance_count"] = (data["Table_Maintenance"] == "Yes").sum()
        
        if "High_Risk_TCode" in data.columns:
            stats["high_risk_tcode_count"] = (data["High_Risk_TCode"] != "").sum()
        
        if "Change_Activity" in data.columns:
            stats["change_activity_count"] = (data["Change_Activity"] != "").sum()
        
        if "Debugging_Related_Event" in data.columns:
            stats["debugging_count"] = (data["Debugging_Related_Event"] == "Yes").sum()
        
        if "Transport_Related_Event" in data.columns:
            stats["transport_count"] = (data["Transport_Related_Event"] == "Yes").sum()
        
        if "Benign_Activity" in data.columns:
            benign_counts = data["Benign_Activity"].value_counts().to_dict()
            stats["benign_activity"] = benign_counts
        
        # Get completeness information from record counter
        try:
            completeness = record_counter.get_counts_for_report()
            stats["completeness"] = completeness
        except Exception as e:
            log_message(f"Warning: Could not get completeness stats: {str(e)}", "WARNING")
        
        log_message("Generated report statistics:")
        log_message(f"  - Total records: {stats['record_count']}")
        log_message(f"  - Unique sessions: {stats['session_count']}")
        log_message(f"  - Unique users: {stats['user_count']}")
        
        if "risk_counts" in stats:
            log_message("  - Risk breakdown:")
            log_message(f"    - Critical: {stats['risk_counts']['Critical']} ({stats['risk_percentages']['Critical']:.1f}%)")
            log_message(f"    - High: {stats['risk_counts']['High']} ({stats['risk_percentages']['High']:.1f}%)")
            log_message(f"    - Medium: {stats['risk_counts']['Medium']} ({stats['risk_percentages']['Medium']:.1f}%)")
            log_message(f"    - Low: {stats['risk_counts']['Low']} ({stats['risk_percentages']['Low']:.1f}%)")
        
        return stats
    
    def _generate_risk_chart(self) -> BytesIO:
        """
        Generate a matplotlib chart for risk distribution.
        
        Returns:
            BytesIO: PNG image of the chart
        """
        # This is a helper method that can be overridden by subclasses
        # Default implementation returns None
        return None
    
    @abstractmethod
    def _create_output_file(self, data, statistics, output_path):
        """
        Create the output file in the appropriate format.
        
        Args:
            data: The prepared session data
            statistics: The generated statistics
            output_path: Where to save the output file
            
        Returns:
            bool: Success status
        """
        pass


class ExcelOutputGenerator(OutputGenerator):
    """
    Generate formatted Excel output reports.
    
    This class specializes the OutputGenerator to create Excel format reports
    with rich formatting, conditional formatting, and data visualization.
    """
    
    def _create_output_file(self, data, statistics, output_path):
        """
        Create a formatted Excel output file according to new unified format requirements.
        
        Args:
            data: The prepared session data
            statistics: The generated statistics
            output_path: Where to save the output file
            
        Returns:
            bool: Success status
        """
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            # Create a risk condition flag
            has_risk_data = "risk_level" in data.columns
            
            # Create Excel writer
            with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:
                wb = writer.book
                
                # Create main Unified_Audit_Timeline sheet
                log_message("Creating main Unified_Audit_Timeline sheet")
                sheet_name = "Unified_Audit_Timeline"
                data.to_excel(writer, sheet_name=sheet_name, index=False, na_rep="")
                ws_main = writer.sheets[sheet_name]
                
                # Apply formatting to main sheet
                self._apply_excel_formatting(ws_main, data, wb)
                
                # Create summary sheet
                log_message("Creating Summary sheet")
                self._create_summary_sheet(wb, writer, statistics)
                
                # Create legends sheet
                log_message("Creating Legend sheet")
                self._create_legend_sheet(wb, writer)
            
            log_message(f"Excel report saved to {output_path}")
            return True
            
        except Exception as e:
            log_error(e, "Error creating Excel output")
            return False
    
    def _apply_excel_formatting(self, worksheet, df, workbook):
        """
        Apply formatting to Excel worksheet.
        
        Args:
            worksheet: The xlsxwriter worksheet
            df: The dataframe being written
            workbook: The xlsxwriter workbook
        """
        # Format headers
        self._format_headers(worksheet, df, workbook)
        
        # Set column widths
        self._set_column_widths(worksheet, df)
        
        # Add autofilter and freeze panes
        worksheet.autofilter(0, 0, len(df), len(df.columns) - 1)
        worksheet.freeze_panes(1, 0)
        
        # Apply conditional formatting based on risk level
        self._apply_risk_conditional_formatting(worksheet, df, workbook)
    
    def _format_headers(self, worksheet, df, workbook):
        """
        Format Excel worksheet headers with color-coded categories.
        
        Args:
            worksheet: The xlsxwriter worksheet
            df: The dataframe being written
            workbook: The xlsxwriter workbook
        """
        # Create formats for each source type
        header_formats = {}
        for source, color in SOURCE_COLORS.items():
            header_formats[source] = workbook.add_format({
                'bold': True,
                'bg_color': color,
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
        
        # Default format for unknown sources
        default_format = workbook.add_format({
            'bold': True,
            'bg_color': '#DDDDDD',
            'border': 1,
            'text_wrap': True,
            'valign': 'top'
        })
        
        # Create custom color formats from config
        custom_color_formats = {}
        custom_colors = self.config.get("header_colors", {})
        for col_name, color in custom_colors.items():
            custom_color_formats[col_name] = workbook.add_format({
                'bold': True,
                'bg_color': color,
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
        
        # Apply formatting to each column header
        for i, col in enumerate(df.columns):
            # Check if column has a custom color defined
            if col in custom_colors:
                fmt = custom_color_formats[col]
            else:
                # Otherwise use source-based coloring
                source = self.column_mapping.get(col, "Generated")
                fmt = header_formats.get(source, default_format)
            
            worksheet.write(0, i, col, fmt)
    
    def _set_column_widths(self, worksheet, df):
        """
        Set appropriate column widths based on content type.
        
        Args:
            worksheet: The xlsxwriter worksheet
            df: The dataframe being written
        """
        for i, col in enumerate(df.columns):
            # Set appropriate column widths based on content type
            width = max(len(str(col)) + 2, 15)
            
            # Adjust width based on column content type
            if any(x in col.lower() for x in ["factors", "rationale", "description", "notes", "observations", "response", "conclusion"]):
                width = 100  # Extra wide for detailed text
            elif any(x in col.lower() for x in ["msg", "text", "message"]):
                width = 60   # Wide for messages
            elif any(x in col.lower() for x in ["timestamp", "datetime", "date"]):
                width = 20   # Medium for dates/times
            elif any(x in col.lower() for x in ["table", "object"]):
                width = 25   # Medium-wide for tables/objects
            elif "risk_level" in col.lower():
                width = 10   # Narrow for risk levels
            elif "session" in col.lower():
                width = 25   # Medium for session IDs
            elif "tcode_description" in col.lower() or "event_description" in col.lower() or "table_description" in col.lower():
                width = 40   # Wide for descriptive columns
            elif col in ["Table_Maintenance", "High_Risk_TCode", "Transport_Related_Event", "Debugging_Related_Event"]:
                width = 20   # Medium for flag columns
            elif col in ["Change_Activity", "Benign_Activity"]:
                width = 25   # Medium-wide for activity classification
            elif col in ["TCode", "Event"]:
                width = 15   # Standard for code columns
            elif col in ["User", "Source"]:
                width = 15   # Standard for basic identifiers
            elif col in ["Old_Value", "New_Value"]:
                width = 30   # Wide for change values
            
            worksheet.set_column(i, i, width)
    
    def _apply_risk_conditional_formatting(self, worksheet, df, workbook):
        """
        Apply conditional formatting based on risk levels.
        
        Args:
            worksheet: The xlsxwriter worksheet
            df: The dataframe being written
            workbook: The xlsxwriter workbook
        """
        if 'risk_level' not in df.columns:
            return
            
        # Create formats for each risk level
        risk_formats = {}
        for risk, color in RISK_COLORS.items():
            font_color = '#FFFFFF' if risk == 'Critical' else '#000000'
            risk_formats[risk] = workbook.add_format({
                'bg_color': color,
                'font_color': font_color
            })
        
        # Find the column index for risk_level
        risk_col_idx = None
        for i, col in enumerate(df.columns):
            if col == 'risk_level':
                risk_col_idx = i
                break
                
        if risk_col_idx is None:
            return
            
        # Apply conditional formatting for each risk level to the entire row
        for risk, fmt in risk_formats.items():
            worksheet.conditional_format(1, 0, len(df), len(df.columns) - 1, {
                'type': 'formula',
                'criteria': f'=${chr(65 + risk_col_idx)}2="{risk}"',
                'format': fmt
            })
    
    def _create_summary_sheet(self, workbook, writer, statistics):
        """
        Create a summary sheet with statistics and visualizations.
        
        Args:
            workbook: The xlsxwriter workbook
            writer: The pandas ExcelWriter
            statistics: The statistics dictionary
        """
        # Create summary data for the sheet
        if "risk_counts" in statistics:
            summary_data = {
                'Category': ['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk', 'Total'],
                'Count': [
                    statistics["risk_counts"]["Critical"],
                    statistics["risk_counts"]["High"],
                    statistics["risk_counts"]["Medium"],
                    statistics["risk_counts"]["Low"],
                    statistics["record_count"]
                ]
            }
        else:
            summary_data = {
                'Category': ['Total Records'],
                'Count': [statistics["record_count"]]
            }
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name="Summary", index=False, na_rep="")
        
        # Get summary worksheet
        summary_worksheet = writer.sheets["Summary"]
        
        # Apply header format
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4F81BD',
            'font_color': 'white',
            'border': 1,
            'text_wrap': True,
            'valign': 'top'
        })
        
        for col_num, col_name in enumerate(summary_df.columns):
            summary_worksheet.write(0, col_num, col_name, header_format)
        
        # Set column widths
        summary_worksheet.set_column(0, 0, 20)
        summary_worksheet.set_column(1, 1, 15)
        
        # Add a chart if we have risk data
        if "risk_counts" in statistics:
            chart = workbook.add_chart({'type': 'pie'})
            
            # Configure the chart - only include risk rows (excluding Total)
            chart.add_series({
                'name': 'Risk Distribution',
                'categories': ['Summary', 1, 0, 4, 0],  # Include rows 1-4 (Critical, High, Medium, Low)
                'values': ['Summary', 1, 1, 4, 1],      # Include corresponding values
                'points': [
                    {'fill': {'color': RISK_COLORS["Critical"]}},  # Critical
                    {'fill': {'color': RISK_COLORS["High"]}},      # High
                    {'fill': {'color': RISK_COLORS["Medium"]}},    # Medium
                    {'fill': {'color': RISK_COLORS["Low"]}}        # Low
                ]
            })
            
            chart.set_title({'name': 'Risk Distribution'})
            chart.set_style(10)
            
            # Insert the chart into the summary worksheet
            summary_worksheet.insert_chart('D2', chart)
        
        # Activity Analysis Statistics
        row = 10
        
        # Add session statistics
        summary_worksheet.write(row, 0, "Session Statistics:", header_format)
        row += 1
        summary_worksheet.write(row, 0, "Total Records:")
        summary_worksheet.write(row, 1, statistics["record_count"])
        row += 1
        summary_worksheet.write(row, 0, "Unique Sessions:")
        summary_worksheet.write(row, 1, statistics["session_count"])
        row += 1
        summary_worksheet.write(row, 0, "Unique Users:")
        summary_worksheet.write(row, 1, statistics["user_count"])
        row += 2
        
        # Add activity statistics if available
        if any(x in statistics for x in ["table_maintenance_count", "high_risk_tcode_count", 
                                        "change_activity_count", "debugging_count", "transport_count"]):
            summary_worksheet.write(row, 0, "Activity Analysis:", header_format)
            row += 1
            
            if "table_maintenance_count" in statistics:
                summary_worksheet.write(row, 0, "Table Maintenance:")
                summary_worksheet.write(row, 1, statistics["table_maintenance_count"])
                row += 1
                
            if "high_risk_tcode_count" in statistics:
                summary_worksheet.write(row, 0, "High Risk TCodes:")
                summary_worksheet.write(row, 1, statistics["high_risk_tcode_count"])
                row += 1
                
            if "change_activity_count" in statistics:
                summary_worksheet.write(row, 0, "Change Activities:")
                summary_worksheet.write(row, 1, statistics["change_activity_count"])
                row += 1
                
            if "debugging_count" in statistics:
                summary_worksheet.write(row, 0, "Debugging Events:")
                summary_worksheet.write(row, 1, statistics["debugging_count"])
                row += 1
                
            if "transport_count" in statistics:
                summary_worksheet.write(row, 0, "Transport Events:")
                summary_worksheet.write(row, 1, statistics["transport_count"])
                row += 1
            
            row += 1
        
        # Add benign activity breakdown if available
        if "benign_activity" in statistics and statistics["benign_activity"]:
            summary_worksheet.write(row, 0, "Benign Activity Breakdown:", header_format)
            row += 1
            
            for activity, count in statistics["benign_activity"].items():
                if activity:  # Only show non-empty activity types
                    summary_worksheet.write(row, 0, activity + ":")
                    summary_worksheet.write(row, 1, count)
                    row += 1
                    
            row += 1
        
        # Add timestamp
        summary_worksheet.write(row, 0, "Generated On:", header_format)
        summary_worksheet.write(row, 1, statistics["timestamp"])
        
        # Add completeness information if available
        if "completeness" in statistics:
            self._add_completeness_to_summary(summary_worksheet, statistics["completeness"], workbook, row + 2)
    
    def _add_completeness_to_summary(self, worksheet, completeness, workbook, start_row):
        """
        Add completeness information to summary sheet.
        
        Args:
            worksheet: The summary worksheet
            completeness: Completeness statistics
            workbook: The xlsxwriter workbook
            start_row: Starting row for completeness section
        """
        row = start_row
        
        # Section header
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4F81BD',
            'font_color': 'white',
            'border': 1
        })
        
        worksheet.write(row, 0, "Data Completeness", header_format)
        worksheet.write(row, 1, f"{completeness.get('completeness_score', 0):.1f}%", header_format)
        row += 1
        
        # Add file information
        source_files = completeness.get("source_files", [])
        if source_files:
            for source in source_files:
                source_type = source.get("source_type", "Unknown")
                file_name = os.path.basename(source.get("file_name", "Unknown"))
                original = source.get("original_count", 0)
                final = source.get("final_count", 0)
                
                worksheet.write(row, 0, f"{source_type.title()} Records:")
                worksheet.write(row, 1, f"{final}/{original} ({final/original*100 if original > 0 else 0:.1f}%)")
                row += 1
    
    def _create_legend_sheet(self, workbook, writer):
        """
        Create a legend sheet explaining color coding.
        
        Args:
            workbook: The xlsxwriter workbook
            writer: The pandas ExcelWriter
        """
        # Create header legend
        header_legend_data = []
        header_legend_data.append(["Header Color Legend", ""])
        for source, color in SOURCE_COLORS.items():
            description = ""
            if source == "SM20":
                description = "SM20 Security Audit Log fields"
            elif source == "CDHDR":
                description = "CDHDR Change Document Header fields"
            elif source == "CDPOS":
                description = "CDPOS Change Document Item fields"
            elif source == "Generated":
                description = "Generated or derived fields by the tool"
            elif source == "SysAid":
                description = "SysAid ticket information fields"
            elif source == "Eviden":
                description = "Eviden-specific columns (light green)"
            elif source == "Analysis":
                description = "Analysis flag columns (peach)"
            
            header_legend_data.append([source, description])
        
        # Add blank row for spacing
        header_legend_data.append(["", ""])
        
        # Add risk level legend
        header_legend_data.append(["Risk Level Legend", ""])
        for risk, color in RISK_COLORS.items():
            description = ""
            if risk == "Critical":
                description = "Critical Risk - Requires immediate attention"
            elif risk == "High":
                description = "High Risk - Significant security concern"
            elif risk == "Medium":
                description = "Medium Risk - Potential security issue"
            elif risk == "Low":
                description = "Low Risk - Minimal security concern"
            
            header_legend_data.append([risk, description])
        
        # Add blank row for spacing
        header_legend_data.append(["", ""])
        
        # Add analysis flags legend
        header_legend_data.append(["Analysis Flags Legend", ""])
        
        flag_descriptions = [
            ["Table_Maintenance", "Indicates table maintenance activities (SM30, SM31, SE16, etc.)"],
            ["High_Risk_TCode", "Categorizes high-risk transaction codes by purpose (Development, Security, etc.)"],
            ["Change_Activity", "Shows activity type using standard codes (01-Insert, 02-Update, 06-Delete, etc.)"],
            ["Transport_Related_Event", "Flags transport-related activities (STMS, SE01, SE09, etc.)"],
            ["Debugging_Related_Event", "Flags debugging activities (SE24, SE37, SE38, breakpoints, etc.)"],
            ["Benign_Activity", "Identifies standard activities (Logon, Logoff, Display, Session Manager)"]
        ]
        
        for flag_desc in flag_descriptions:
            header_legend_data.append(flag_desc)
        
        # Write legend to sheet
        legend_df = pd.DataFrame(header_legend_data, columns=["Category", "Description"])
        legend_df.to_excel(writer, sheet_name="Legend", index=False, header=False)
        
        # Get legend worksheet
        legend_worksheet = writer.sheets["Legend"]
        
        # Define formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4F81BD',
            'font_color': 'white',
            'border': 1
        })
        
        subheader_format = workbook.add_format({
            'bold': True,
            'italic': True
        })
        
        # Apply formatting to headers
        legend_worksheet.write(0, 0, "Category", header_format)
        legend_worksheet.write(0, 1, "Description", header_format)
        
        # Format section headers
        # Header Color Legend
        legend_worksheet.write(1, 0, "Header Color Legend", subheader_format)
        
        # Add color samples for header colors
        row = 2
        for source, color in SOURCE_COLORS.items():
            cell_fmt = workbook.add_format({'bg_color': color})
            legend_worksheet.write(row, 0, source, cell_fmt)
            row += 1
            
        # Risk Level Legend (after the blank row)
        row += 1  # Skip the blank row
        legend_worksheet.write(row, 0, "Risk Level Legend", subheader_format)
        row += 1
        
        # Add color samples for risk levels
        for risk, color in RISK_COLORS.items():
            font_color = "#FFFFFF" if risk == "Critical" else "#000000"
            cell_fmt = workbook.add_format({'bg_color': color, 'font_color': font_color})
            legend_worksheet.write(row, 0, risk, cell_fmt)
            row += 1
        
        # Set column widths
        legend_worksheet.set_column(0, 0, 25)
        legend_worksheet.set_column(1, 1, 80)


class CsvOutputGenerator(OutputGenerator):
    """
    Generate CSV output reports.
    
    This class specializes the OutputGenerator to create simple CSV format reports.
    """
    
    def _create_output_file(self, data, statistics, output_path):
        """
        Create a CSV output file.
        
        Args:
            data: The prepared session data
            statistics: The generated statistics
            output_path: Where to save the output file
            
        Returns:
            bool: Success status
        """
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            # Write main data to CSV
            data.to_csv(output_path, index=False)
            
            # Create statistics summary file
            base_dir = os.path.dirname(output_path)
            base_name = os.path.splitext(os.path.basename(output_path))[0]
            stats_path = os.path.join(base_dir, f"{base_name}_Summary.csv")
            self._create_stats_summary_csv(statistics, stats_path)
            
            log_message(f"CSV report saved to {output_path}")
            log_message(f"Summary statistics saved to {stats_path}")
            return True
            
        except Exception as e:
            log_error(e, "Error creating CSV output")
            return False
    
    def _create_stats_summary_csv(self, statistics, output_path):
        """
        Create a CSV summary of statistics.
        
        Args:
            statistics: The statistics dictionary
            output_path: Where to save the statistics CSV
        """
        # Create summary data rows
        summary_rows = []
        
        # Add basic statistics
        summary_rows.append(["Total Records", statistics["record_count"]])
        summary_rows.append(["Unique Sessions", statistics["session_count"]])
        summary_rows.append(["Unique Users", statistics["user_count"]])
        
        # Add timestamp
        summary_rows.append(["Generated On", statistics["timestamp"]])
        
        # Add risk statistics if available
        if "risk_counts" in statistics:
            summary_rows.append([])  # Empty row as separator
            summary_rows.append(["Risk Level", "Count", "Percentage"])
            summary_rows.append(["Critical", 
                                statistics["risk_counts"]["Critical"],
                                f"{statistics['risk_percentages']['Critical']:.1f}%"])
            summary_rows.append(["High", 
                                statistics["risk_counts"]["High"],
                                f"{statistics['risk_percentages']['High']:.1f}%"])
            summary_rows.append(["Medium", 
                                statistics["risk_counts"]["Medium"],
                                f"{statistics['risk_percentages']['Medium']:.1f}%"])
            summary_rows.append(["Low", 
                                statistics["risk_counts"]["Low"],
                                f"{statistics['risk_percentages']['Low']:.1f}%"])
        
        # Add activity statistics if available
        if any(x in statistics for x in ["table_maintenance_count", "high_risk_tcode_count", 
                                         "change_activity_count", "debugging_count", "transport_count"]):
            summary_rows.append([])  # Empty row as separator
            summary_rows.append(["Activity Analysis", "Count"])
            
            if "table_maintenance_count" in statistics:
                summary_rows.append(["Table Maintenance", statistics["table_maintenance_count"]])
                
            if "high_risk_tcode_count" in statistics:
                summary_rows.append(["High Risk TCodes", statistics["high_risk_tcode_count"]])
                
            if "change_activity_count" in statistics:
                summary_rows.append(["Change Activities", statistics["change_activity_count"]])
                
            if "debugging_count" in statistics:
                summary_rows.append(["Debugging Events", statistics["debugging_count"]])
                
            if "transport_count" in statistics:
                summary_rows.append(["Transport Events", statistics["transport_count"]])
        
        # Add benign activity breakdown if available
        if "benign_activity" in statistics and statistics["benign_activity"]:
            summary_rows.append([])  # Empty row as separator
            summary_rows.append(["Benign Activity", "Count"])
            
            for activity, count in statistics["benign_activity"].items():
                if activity:  # Only show non-empty activity types
                    summary_rows.append([activity, count])
        
        # Add completeness information if available
        if "completeness" in statistics:
            summary_rows.append([])  # Empty row as separator
            summary_rows.append(["Data Completeness", f"{statistics['completeness'].get('completeness_score', 0):.1f}%"])
            
            source_files = statistics["completeness"].get("source_files", [])
            if source_files:
                for source in source_files:
                    source_type = source.get("source_type", "Unknown")
                    original = source.get("original_count", 0)
                    final = source.get("final_count", 0)
                    pct = final/original*100 if original > 0 else 0
                    summary_rows.append([f"{source_type.title()} Records", 
                                        f"{final}/{original}",
                                        f"{pct:.1f}%"])
        
        # Write to CSV
        with open(output_path, 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerows(summary_rows)
