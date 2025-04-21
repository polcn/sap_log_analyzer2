#!/usr/bin/env python3
"""
SAP Audit Tool - Output Completeness Extensions

This module contains functions to enhance the Excel output with record count
and data completeness information.
"""

import pandas as pd
from datetime import datetime

def log_message(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def add_data_completeness_section(workbook, worksheet, record_counter, row_offset=10):
    """
    Add a data completeness section to the summary worksheet.
    
    Args:
        workbook: The xlsxwriter workbook object
        worksheet: The summary worksheet to add the section to
        record_counter: The RecordCounter instance with record counts
        row_offset: Row to start adding the section (after the risk summary)
    """
    # Create formats
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#4F81BD',
        'font_color': 'white',
        'border': 1,
        'text_wrap': True,
        'valign': 'top'
    })
    
    subheader_format = workbook.add_format({
        'bold': True,
        'bg_color': '#B8CCE4',
        'border': 1
    })
    
    cell_format = workbook.add_format({
        'border': 1
    })
    
    percent_format = workbook.add_format({
        'border': 1,
        'num_format': '0.00%'
    })
    
    # Start row for the section
    current_row = row_offset
    
    # Add section header
    worksheet.merge_range(current_row, 0, current_row, 4, "Data Completeness", header_format)
    current_row += 1
    
    # Add overall completeness score
    completeness_score = record_counter.counts["timeline"]["completeness_score"] / 100.0  # Convert to decimal for percentage format
    worksheet.write(current_row, 0, "Overall Completeness Score:", subheader_format)
    worksheet.write(current_row, 1, completeness_score, percent_format)
    current_row += 2
    
    # Add column headers for source files table
    worksheet.write(current_row, 0, "Source Type", subheader_format)
    worksheet.write(current_row, 1, "File Name", subheader_format)
    worksheet.write(current_row, 2, "Original Records", subheader_format)
    worksheet.write(current_row, 3, "Final Records", subheader_format)
    worksheet.write(current_row, 4, "Inclusion Rate", subheader_format)
    current_row += 1
    
    # Add data for each source type
    for source_type in ["sm20", "cdhdr", "cdpos", "sysaid"]:
        source_data = record_counter.counts[source_type]
        if source_data["original_count"] > 0:
            # Calculate inclusion rate
            inclusion_rate = source_data["final_count"] / source_data["original_count"] if source_data["original_count"] > 0 else 0
            
            # Write source data
            worksheet.write(current_row, 0, source_type.upper(), cell_format)
            worksheet.write(current_row, 1, source_data["file_name"], cell_format)
            worksheet.write(current_row, 2, source_data["original_count"], cell_format)
            worksheet.write(current_row, 3, source_data["final_count"], cell_format)
            worksheet.write(current_row, 4, inclusion_rate, percent_format)
            current_row += 1
    
    # Add total row
    total_original = sum(record_counter.counts[src]["original_count"] for src in ["sm20", "cdhdr", "cdpos"])
    total_final = record_counter.counts["timeline"]["total_records"]
    total_rate = total_final / total_original if total_original > 0 else 0
    
    worksheet.write(current_row, 0, "TOTAL", subheader_format)
    worksheet.write(current_row, 1, "", subheader_format)
    worksheet.write(current_row, 2, total_original, subheader_format)
    worksheet.write(current_row, 3, total_final, subheader_format)
    worksheet.write(current_row, 4, total_rate, percent_format)
    current_row += 2
    
    # Add explanation
    worksheet.merge_range(current_row, 0, current_row, 4, "Record Count Explanation:", subheader_format)
    current_row += 1
    
    explanation_text = (
        "Original Records: Total records read from source files\n"
        "Final Records: Records included in the output report\n"
        "Inclusion Rate: Percentage of original records included in the report\n\n"
        "Note: The overall completeness score may exceed 100% if records are duplicated across multiple sources."
    )
    
    explanation_format = workbook.add_format({
        'text_wrap': True,
        'valign': 'top'
    })
    
    worksheet.merge_range(current_row, 0, current_row + 4, 4, explanation_text, explanation_format)
    worksheet.set_row(current_row, 80)  # Set row height to fit the explanation text
    
    # Set column widths
    worksheet.set_column(0, 0, 20)  # Source Type
    worksheet.set_column(1, 1, 30)  # File Name
    worksheet.set_column(2, 2, 15)  # Original Records
    worksheet.set_column(3, 3, 15)  # Final Records
    worksheet.set_column(4, 4, 15)  # Inclusion Rate
    
    log_message("Added data completeness section to summary worksheet")
    
    return current_row + 5  # Return the next available row

def update_summary_with_completeness(workbook, worksheet, record_counter):
    """
    Update the summary worksheet with completeness information.
    This function is intended to be called from generate_excel_output after the initial summary is created.
    
    Args:
        workbook: The xlsxwriter workbook object
        worksheet: The summary worksheet
        record_counter: The RecordCounter instance
    """
    # Find the right place to add the completeness section (after the risk summary)
    # Typically this would be around row 10-12 in the existing summary sheet
    add_data_completeness_section(workbook, worksheet, record_counter, row_offset=12)
