#!/usr/bin/env python3
"""
Comprehensive SysAid Analyzer

This script performs a detailed analysis of SysAid values across all data files in the SAP Log Analyzer project:
1. Analyzes both source Excel files and processed CSV files
2. Detects SysAid values in various formats (with/without prefixes, with/without commas)
3. Reports statistics on unique values, formats, and distribution
"""

import os
import glob
import pandas as pd
from datetime import datetime
import re

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "input")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "sysaid_analysis_results.txt")

# Common SysAid column names (case-insensitive)
SYSAID_COLUMN_PATTERNS = [
    'SYSAID', 'TICKET', 'CR', 'SR', 'CHANGE REQUEST'
]

def log_message(message, level="INFO", file=None):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] {level}: {message}"
    print(formatted_message)
    if file:
        file.write(formatted_message + "\n")

def find_sysaid_columns(df):
    """Find potential SysAid columns based on common naming patterns."""
    sysaid_columns = []
    for col in df.columns:
        for pattern in SYSAID_COLUMN_PATTERNS:
            if pattern in col.upper():
                sysaid_columns.append(col)
                break
    return sysaid_columns

def analyze_sysaid_values(values, file=None):
    """Analyze SysAid values for patterns and formats."""
    # Convert to strings and filter out empty/NaN values
    clean_values = [str(val).strip() for val in values if val and str(val).strip() and str(val).lower() != 'nan']
    
    if not clean_values:
        log_message("No non-empty SysAid values found", file=file)
        return {}
    
    # Count unique values
    unique_values = list(set(clean_values))
    log_message(f"Found {len(unique_values)} unique non-empty SysAid values out of {len(clean_values)} total", file=file)
    
    # Identify value formats
    formats = {
        'numeric_only': 0,       # 123456
        'with_hash': 0,          # #123456
        'with_commas': 0,        # 123,456
        'hash_and_commas': 0,    # #123,456
        'with_prefix': 0,        # SR-123456, CR-123456
        'other': 0               # Any other format
    }
    
    for val in unique_values:
        if re.match(r'^#\d+,\d+$', val):
            formats['hash_and_commas'] += 1
        elif re.match(r'^#\d+$', val):
            formats['with_hash'] += 1
        elif re.match(r'^\d+,\d+$', val):
            formats['with_commas'] += 1
        elif re.match(r'^\d+$', val):
            formats['numeric_only'] += 1
        elif re.match(r'^(SR|CR)-\d+$', val, re.IGNORECASE):
            formats['with_prefix'] += 1
        else:
            formats['other'] += 1
    
    log_message("SysAid value formats:", file=file)
    for format_type, count in formats.items():
        if count > 0:
            log_message(f"  {format_type}: {count} values", file=file)
    
    # Create standardized values (removing prefixes, commas)
    standardized_values = []
    standardization_map = {}
    
    for val in unique_values:
        # Remove any prefix like #, SR-, CR-
        std_val = re.sub(r'^[#]*', '', val)  # First remove hash prefixes
        std_val = re.sub(r'^(SR|CR)-', '', std_val)  # Then remove SR- or CR- prefixes
        # Remove commas
        std_val = std_val.replace(',', '')
        standardized_values.append(std_val)
        standardization_map[val] = std_val
    
    # Count unique standardized values
    unique_standardized = list(set(standardized_values))
    log_message(f"After standardization: {len(unique_standardized)} unique values", file=file)
    
    # Show standardization examples
    log_message("Standardization examples:", file=file)
    examples_shown = 0
    for orig, std in standardization_map.items():
        if orig != std:  # Only show if something changed
            log_message(f"  '{orig}' -> '{std}'", file=file)
            examples_shown += 1
            if examples_shown >= 10:  # Limit to 10 examples
                log_message(f"  (... and {len(standardization_map) - 10} more)", file=file)
                break
    
    return {
        'unique_count': len(unique_values),
        'unique_standardized_count': len(unique_standardized),
        'unique_values': unique_values,
        'unique_standardized': unique_standardized,
        'formats': formats,
        'standardization_map': standardization_map
    }

def analyze_file(file_path, output_file):
    """Analyze a data file for SysAid values."""
    log_message(f"Analyzing file: {file_path}", file=output_file)
    
    try:
        # Determine file type based on extension
        if file_path.lower().endswith('.xlsx') or file_path.lower().endswith('.xls'):
            df = pd.read_excel(file_path)
            file_type = "Excel"
        elif file_path.lower().endswith('.csv'):
            df = pd.read_csv(file_path, encoding='utf-8-sig')
            file_type = "CSV"
        else:
            log_message(f"Unsupported file type: {file_path}", "WARNING", output_file)
            return None
        
        log_message(f"Successfully read {file_type} file with {len(df)} rows and {len(df.columns)} columns", file=output_file)
        
        # Find potential SysAid columns
        sysaid_columns = find_sysaid_columns(df)
        
        if not sysaid_columns:
            log_message(f"No potential SysAid columns found in {file_path}", file=output_file)
            
            # If no obvious SysAid columns, show all columns for reference
            log_message("Available columns:", file=output_file)
            for col in df.columns:
                log_message(f"  {col}", file=output_file)
            
            return None
        
        log_message(f"Found {len(sysaid_columns)} potential SysAid columns: {', '.join(sysaid_columns)}", file=output_file)
        
        # Analyze each potential SysAid column
        results = {}
        for col in sysaid_columns:
            log_message(f"\nAnalyzing column: {col}", file=output_file)
            
            # Get non-NaN values
            non_empty_values = df[col].dropna().tolist()
            
            # Basic stats
            log_message(f"Non-empty values: {len(non_empty_values)} out of {len(df)} rows " + 
                      f"({len(non_empty_values)/len(df)*100:.2f}%)", file=output_file)
            
            # Detailed analysis of values
            col_results = analyze_sysaid_values(non_empty_values, output_file)
            
            if col_results:
                results[col] = col_results
                
                # Show distribution of top values
                value_counts = df[col].value_counts().head(15)
                log_message("\nTop values by frequency:", file=output_file)
                for val, count in value_counts.items():
                    if pd.notna(val) and str(val).strip():
                        log_message(f"  '{val}': {count} rows", file=output_file)
                
                # Show sample of rows with SysAid values
                if len(non_empty_values) > 0:
                    sample_rows = df[df[col].notna() & (df[col] != '')].sample(min(5, len(non_empty_values)))
                    log_message("\nSample rows with SysAid values:", file=output_file)
                    for _, row in sample_rows.iterrows():
                        log_message(f"  SysAid: '{row[col]}' - Sample data: {dict(row[:5])}", file=output_file)
        
        return results
        
    except Exception as e:
        log_message(f"Error analyzing file {file_path}: {str(e)}", "ERROR", output_file)
        return None

def main():
    """Main function to analyze all data files."""
    with open(OUTPUT_FILE, 'w') as output_file:
        log_message("Starting Comprehensive SysAid Analysis", file=output_file)
        
        # Find all potential data files
        excel_files = glob.glob(os.path.join(INPUT_DIR, "*.xlsx"))
        csv_files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))
        
        log_message(f"Found {len(excel_files)} Excel files and {len(csv_files)} CSV files", file=output_file)
        
        # Analyze Excel files first (source data)
        all_results = {'excel': {}, 'csv': {}}
        for file_path in excel_files:
            log_message(f"\n{'='*80}", file=output_file)
            file_name = os.path.basename(file_path)
            results = analyze_file(file_path, output_file)
            if results:
                all_results['excel'][file_name] = results
        
        # Then analyze CSV files (processed data)
        for file_path in csv_files:
            log_message(f"\n{'='*80}", file=output_file)
            file_name = os.path.basename(file_path)
            results = analyze_file(file_path, output_file)
            if results:
                all_results['csv'][file_name] = results
        
        # Compile overall statistics
        log_message(f"\n{'='*80}", file=output_file)
        log_message("OVERALL ANALYSIS SUMMARY", file=output_file)
        log_message(f"{'='*80}", file=output_file)
        
        # Gather all unique SysAid values across all files
        all_unique_values = set()
        all_standardized_values = set()
        
        for file_type, file_results in all_results.items():
            for file_name, columns in file_results.items():
                for col_name, col_results in columns.items():
                    if 'unique_values' in col_results:
                        all_unique_values.update(col_results['unique_values'])
                    if 'unique_standardized' in col_results:
                        all_standardized_values.update(col_results['unique_standardized'])
        
        log_message(f"Total unique SysAid values across all files: {len(all_unique_values)}", file=output_file)
        log_message(f"Total unique standardized SysAid values: {len(all_standardized_values)}", file=output_file)
        
        # List all unique standardized values
        log_message("\nAll unique standardized SysAid values:", file=output_file)
        for i, val in enumerate(sorted(all_standardized_values)):
            log_message(f"  {i+1}. {val}", file=output_file)
        
        log_message(f"\nAnalysis complete. Results saved to: {OUTPUT_FILE}", file=output_file)
        log_message(f"Analysis complete. Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
