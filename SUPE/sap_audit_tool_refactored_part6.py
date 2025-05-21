#!/usr/bin/env python3
"""
SAP Audit Tool - Enhanced Security Analysis Script (Refactored) - Part 6: Output Generation and Main Function
"""

# --- Output Generation ---
def generate_excel_output(risk_data, unmatched_cdpos, unmatched_sm20, output_file, mode="legacy"):
    """Generate a formatted Excel output with the risk assessment results."""
    log_message(f"Generating Excel output in {mode} mode: {output_file}")
    
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        os.makedirs(output_dir, exist_ok=True)
        
        # Create Excel writer
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            # Get workbook
            workbook = writer.book
            
            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#4F81BD',
                'font_color': 'white',
                'border': 1,
                'text_wrap': True,
                'valign': 'top'
            })
            
            high_risk_format = workbook.add_format({'bg_color': HIGH_RISK_COLOR})
            medium_risk_format = workbook.add_format({'bg_color': MEDIUM_RISK_COLOR})
            low_risk_format = workbook.add_format({'bg_color': LOW_RISK_COLOR})
            
            # Write risk assessment data
            if mode == "legacy":
                # Legacy mode output
                sheet_name = "Risk_Assessment"
                risk_data.to_excel(writer, sheet_name=sheet_name, index=False)
                
                # Get worksheet
                worksheet = writer.sheets[sheet_name]
                
                # Apply header format
                for col_num, col_name in enumerate(risk_data.columns):
                    worksheet.write(0, col_num, col_name, header_format)
                
                # Apply conditional formatting based on risk level
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'text',
                    'criteria': 'containing',
                    'value': 'High',
                    'format': high_risk_format
                })
                
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'text',
                    'criteria': 'containing',
                    'value': 'Medium',
                    'format': medium_risk_format
                })
                
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'text',
                    'criteria': 'containing',
                    'value': 'Low',
                    'format': low_risk_format
                })
                
                # Write unmatched data if available
                if len(unmatched_cdpos) > 0:
                    unmatched_cdpos.to_excel(writer, sheet_name="Unmatched_CDPOS", index=False)
                    unmatched_worksheet = writer.sheets["Unmatched_CDPOS"]
                    for col_num, col_name in enumerate(unmatched_cdpos.columns):
                        unmatched_worksheet.write(0, col_num, col_name, header_format)
                
                if len(unmatched_sm20) > 0:
                    unmatched_sm20.to_excel(writer, sheet_name="Unmatched_SM20", index=False)
                    unmatched_worksheet = writer.sheets["Unmatched_SM20"]
                    for col_num, col_name in enumerate(unmatched_sm20.columns):
                        unmatched_worksheet.write(0, col_num, col_name, header_format)
            
            else:
                # Session-based mode output
                sheet_name = "Session_Risk_Assessment"
                risk_data.to_excel(writer, sheet_name=sheet_name, index=False)
                
                # Get worksheet
                worksheet = writer.sheets[sheet_name]
                
                # Apply header format
                for col_num, col_name in enumerate(risk_data.columns):
                    worksheet.write(0, col_num, col_name, header_format)
                
                # Apply conditional formatting based on risk level
                risk_col_idx = risk_data.columns.get_loc('risk_level')
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'cell',
                    'criteria': 'equal to',
                    'value': '"High"',
                    'format': high_risk_format
                })
                
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'cell',
                    'criteria': 'equal to',
                    'value': '"Medium"',
                    'format': medium_risk_format
                })
                
                worksheet.conditional_format(1, 0, len(risk_data), len(risk_data.columns)-1, {
                    'type': 'cell',
                    'criteria': 'equal to',
                    'value': '"Low"',
                    'format': low_risk_format
                })
            
            # Add summary sheet
            summary_data = {
                'Category': ['High Risk', 'Medium Risk', 'Low Risk', 'Total'],
                'Count': [
                    len(risk_data[risk_data['risk_level'] == 'High']),
                    len(risk_data[risk_data['risk_level'] == 'Medium']),
                    len(risk_data[risk_data['risk_level'] == 'Low']),
                    len(risk_data)
                ]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name="Summary", index=False)
            
            # Get summary worksheet
            summary_worksheet = writer.sheets["Summary"]
            
            # Apply header format
            for col_num, col_name in enumerate(summary_df.columns):
                summary_worksheet.write(0, col_num, col_name, header_format)
            
            # Add a chart
            chart = workbook.add_chart({'type': 'pie'})
            
            # Configure the chart
            chart.add_series({
                'name': 'Risk Distribution',
                'categories': ['Summary', 1, 0, 3, 0],
                'values': ['Summary', 1, 1, 3, 1],
                'points': [
                    {'fill': {'color': HIGH_RISK_COLOR}},
                    {'fill': {'color': MEDIUM_RISK_COLOR}},
                    {'fill': {'color': LOW_RISK_COLOR}}
                ]
            })
            
            chart.set_title({'name': 'Risk Distribution'})
            chart.set_style(10)
            
            # Insert the chart into the summary worksheet
            summary_worksheet.insert_chart('D2', chart)
            
            # Add autofilter to all sheets
            worksheet.autofilter(0, 0, len(risk_data), len(risk_data.columns)-1)
            
            # Freeze panes
            worksheet.freeze_panes(1, 0)
            
        log_message(f"Excel output successfully generated: {output_file}")
        return True
    
    except Exception as e:
        log_message(f"Error generating Excel output: {str(e)}", "ERROR")
        return False

# --- Main Function ---
def main():
    """Main function to execute the SAP audit tool."""
    start_time = datetime.now()
    log_message(f"Starting SAP Audit Tool v{VERSION}...")
    
    try:
        # Step 1: Check if session timeline file exists
        session_timeline = load_session_timeline()
        
        if session_timeline is not None:
            # Session-based mode
            log_message("Session timeline found. Running in session-based mode.")
            
            # Prepare session data
            prepared_session_data = prepare_session_data(session_timeline)
            
            # Assess risk
            risk_assessment = assess_risk_session(prepared_session_data)
            
            # Generate output
            generate_excel_output(risk_assessment, pd.DataFrame(), pd.DataFrame(), OUTPUT_FILE, mode="session")
            
        else:
            # Legacy mode (direct correlation)
            log_message("No session timeline found. Running in legacy correlation mode.")
            
            # Load input files
            sm20, cdhdr, cdpos = load_input_files()
            
            # Prepare data
            prepared_sm20 = prepare_sm20(sm20)
            cdpos_merged, cdhdr_user_col = prepare_change_documents(cdhdr, cdpos)
            
            # Correlate logs
            correlated_data, sm20_for_unmatched, cdpos_for_unmatched = correlate_logs(
                prepared_sm20, cdpos_merged, SM20_USER_COL, cdhdr_user_col
            )
            
            # Identify unmatched records
            unmatched_cdpos, unmatched_sm20 = identify_unmatched_records(
                correlated_data, cdpos_for_unmatched, sm20_for_unmatched
            )
            
            # Assess risk
            risk_assessment = assess_risk_legacy(correlated_data, unmatched_cdpos, unmatched_sm20)
            
            # Generate output
            generate_excel_output(risk_assessment, unmatched_cdpos, unmatched_sm20, OUTPUT_FILE, mode="legacy")
        
        # Calculate elapsed time
        elapsed_time = (datetime.now() - start_time).total_seconds()
        log_message(f"Processing complete in {elapsed_time:.2f} seconds.")
        
        log_message(f"Audit report saved to: {os.path.abspath(OUTPUT_FILE)}")
        print(f"\nAudit report saved to: {os.path.abspath(OUTPUT_FILE)}")
        
        return True
    
    except Exception as e:
        log_message(f"Error in main execution: {str(e)}", "ERROR")
        import traceback
        log_message(f"Stack trace: {traceback.format_exc()}", "ERROR")
        return False

# --- Script Entry Point ---
if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT TOOL v{} ".format(VERSION).center(80, "*") + "\n"
    banner += " Enhanced Security Analysis for SAP Logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    main()
