#!/usr/bin/env python3
"""
SAP Audit Tool - Output Generation Module

This module provides functionality for generating formatted output reports from SAP audit data.
It implements the Template Method pattern for different output formats and includes
configuration-based templating and visualization capabilities.

Key features:
- OutputGenerator abstract base class implementing Template Method pattern
- Concrete implementations for Excel and CSV output formats
- Configuration-based templating for consistent reporting
- Visualization of risk statistics
- Exception handling with handle_exception decorator
- Standardized logging
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
from sap_audit_config import PATHS, REPORTING, COLUMNS, SETTINGS
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
            'SysAid Request User': 'SysAid'
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
        
        # Organize columns according to configuration if specified
        if "column_order" in self.config:
            ordered_cols = [col for col in self.config["column_order"] if col in prepared_data.columns]
            remaining_cols = [col for col in prepared_data.columns if col not in ordered_cols]
            prepared_data = prepared_data[ordered_cols + remaining_cols]
        
        log_message(f"Prepared {len(prepared_data)} records for reporting")
        return prepared_data
    
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
        Create a formatted Excel output file.
        
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
            
            # Create filtered datasets for special sheets
            special_sheets = self._create_special_sheets(data)
            
            # Create Excel writer
            with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:
                wb = writer.book
                
                # Create main timeline sheet
                log_message("Creating main timeline sheet")
                data.to_excel(writer, sheet_name="Session_Timeline", index=False, na_rep="")
                ws_main = writer.sheets["Session_Timeline"]
                self._apply_excel_formatting(ws_main, data, wb)
                
                # Create special sheets
                for sheet_name, sheet_data in special_sheets.items():
                    if not sheet_data.empty:
                        log_message(f"Creating {sheet_name} sheet")
                        sheet_data.to_excel(writer, sheet_name=sheet_name, index=False, na_rep="")
                        ws = writer.sheets[sheet_name]
                        self._apply_excel_formatting(ws, sheet_data, wb)
                
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
        Format Excel worksheet headers.
        
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
        Set appropriate column widths.
        
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
        
        # Apply conditional formatting for each risk level
        for risk, fmt in risk_formats.items():
            worksheet.conditional_format(1, 0, len(df), len(df.columns) - 1, {
                'type': 'cell',
                'criteria': 'equal to',
                'value': f'"{risk}"',
                'format': fmt
            })
    
    def _create_special_sheets(self, data):
        """
        Create special filtered sheets for the report.
        
        Args:
            data: The main session data
            
        Returns:
            Dict of sheet names to dataframes
        """
        special_sheets = {}
        
        # Create debug events sheet
        debug_events = self._extract_debug_events(data)
        if not debug_events.empty:
            special_sheets["Debug_Activities"] = debug_events
        
        # Create high risk events sheet
        if "risk_level" in data.columns:
            high_risk = data[data["risk_level"].isin(["Critical", "High"])]
            if not high_risk.empty:
                special_sheets["High_Risk_Events"] = high_risk
        
        # Create SysAid tickets sheet
        if "SYSAID #" in data.columns:
            sysaid_events = data[data["SYSAID #"] != ""].copy()
            if not sysaid_events.empty:
                special_sheets["SysAid_Tickets"] = sysaid_events
        
        return special_sheets
    
    def _extract_debug_events(self, data):
        """
        Extract debug-related events.
        
        Args:
            data: The main session data
            
        Returns:
            DataFrame with debug events
        """
        # Create query conditions based on column availability
        conditions = []
        
        # Check for debug markers in Variable_2
        if 'Variable_2' in data.columns:
            conditions.append(data['Variable_2'].str.contains('I!|D!|G!', na=False))
        
        # FireFighter accounts with high risk activities
        if 'User' in data.columns and 'risk_level' in data.columns:
            conditions.append(
                (data['User'].str.startswith('FF_', na=False)) & 
                (data['risk_level'].isin(['High', 'Critical']))
            )
        
        # Check for debug mentions in risk description or risk_factors
        risk_desc_col = 'risk_description' if 'risk_description' in data.columns else 'risk_factors'
        if risk_desc_col in data.columns:
            conditions.append(
                data[risk_desc_col].str.contains('debug session detected|dynamic abap code execution',
                                               case=False, na=False)
            )
        
        # Combine conditions with OR logic
        if conditions:
            combined_condition = conditions[0]
            for condition in conditions[1:]:
                combined_condition = combined_condition | condition
            debug_events = data[combined_condition]
        else:
            debug_events = pd.DataFrame(columns=data.columns)
        
        return debug_events
    
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
        summary_worksheet.set_column(0, 0, 15)
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
        
        # Add session statistics
        row = 10
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
        
        # Add timestamp
        row += 2
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
        header_legend = pd.DataFrame({
            'Source': list(SOURCE_COLORS.keys()),
            'Description': [
                'SM20 Security Audit Log fields',
                'CDHDR Change Document Header fields',
                'CDPOS Change Document Item fields',
                'Generated or derived fields by the tool',
                'SysAid ticket information fields'
            ]
        })
        
        # Create risk legend
        risk_legend = pd.DataFrame({
            'Risk Level': list(RISK_COLORS.keys()),
            'Description': [
                'Critical Risk - Requires immediate attention',
                'High Risk - Significant security concern',
                'Medium Risk - Potential security issue',
                'Low Risk - Minimal security concern'
            ]
        })
        
        # Write legends to sheet
        header_legend.to_excel(writer, sheet_name="Legend", index=False, startrow=0, na_rep="")
        risk_legend.to_excel(writer, sheet_name="Legend", index=False, startrow=len(header_legend) + 2, na_rep="")
        
        # Get legend worksheet
        legend_worksheet = writer.sheets["Legend"]
        
        # Format header legend
        for idx, source in enumerate(header_legend["Source"]):
            color = SOURCE_COLORS.get(source, "#FFFFFF")
            cell_fmt = workbook.add_format({'bg_color': color, 'border': 1})
            legend_worksheet.write(idx + 1, 0, source, cell_fmt)
        
        # Format risk legend
        for idx, risk in enumerate(risk_legend["Risk Level"]):
            color = RISK_COLORS.get(risk, "#FFFFFF")
            font_color = "#FFFFFF" if risk == "Critical" else "#000000"
            cell_fmt = workbook.add_format({'bg_color': color, 'font_color': font_color, 'border': 1})
            legend_worksheet.write(idx + len(header_legend) + 3, 0, risk, cell_fmt)
        
        # Set column widths
        legend_worksheet.set_column(0, 0, 15)
        legend_worksheet.set_column(1, 1, 50)


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
            
            # Create special sheets as separate CSV files
            special_sheets = self._create_special_sheets(data)
            
            # Get base name and directory for additional CSVs
            base_dir = os.path.dirname(output_path)
            base_name = os.path.splitext(os.path.basename(output_path))[0]
            
            # Create CSV files for special sheets
            for sheet_name, sheet_data in special_sheets.items():
                if not sheet_data.empty:
                    special_path = os.path.join(base_dir, f"{base_name}_{sheet_name}.csv")
                    sheet_data.to_csv(special_path, index=False)
                    log_message(f"Created special sheet CSV: {special_path}")
            
            # Create statistics summary file
            stats_path = os.path.join(base_dir, f"{base_name}_Summary.csv")
            self._create_stats_summary_csv(statistics, stats_path)
            
            log_message(f"CSV report saved to {output_path}")
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
        
        log_message(f"Statistics summary saved to {output_path}")
    
    def _create_special_sheets(self, data):
        """
        Create special filtered datasets.
        
        Args:
            data: The main session data
            
        Returns:
            Dict of sheet names to dataframes
        """
        special_sheets = {}
        
        # Create high risk events sheet
        if "risk_level" in data.columns:
            high_risk = data[data["risk_level"].isin(["Critical", "High"])]
            if not high_risk.empty:
                special_sheets["High_Risk_Events"] = high_risk
        
        # Create debug events sheet if we can detect them
        debug_events = pd.DataFrame()
        
        # Check for debug markers in Variable_2
        if 'Variable_2' in data.columns:
            debug_variable = data[data['Variable_2'].str.contains('I!|D!|G!', na=False)]
            if not debug_variable.empty:
                debug_events = pd.concat([debug_events, debug_variable])
        
        # FireFighter accounts with high risk
        if 'User' in data.columns and 'risk_level' in data.columns:
            ff_high_risk = data[(data['User'].str.startswith('FF_', na=False)) & 
                              (data['risk_level'].isin(['High', 'Critical']))]
            if not ff_high_risk.empty:
                debug_events = pd.concat([debug_events, ff_high_risk])
        
        # Remove duplicates if any
        if not debug_events.empty:
            debug_events = debug_events.drop_duplicates()
            special_sheets["Debug_Activities"] = debug_events
        
        # Create SysAid tickets sheet
        if "SYSAID #" in data.columns:
            sysaid_events = data[data["SYSAID #"] != ""].copy()
            if not sysaid_events.empty:
                special_sheets["SysAid_Tickets"] = sysaid_events
        
        return special_sheets
