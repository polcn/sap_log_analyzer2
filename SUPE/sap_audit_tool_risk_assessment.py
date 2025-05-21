#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Functions

This module contains the risk assessment functions for the SAP Audit Tool.
"""

def get_sensitive_tables():
    """Return a set of sensitive SAP tables to monitor."""
    return {
        # Security Tables
        "USR01", "USR02", "USR04", "USR10", "USR12", "USR21", "USR40", "UST10C", "UST04",
        "AGR_1251", "AGR_USERS", "AGR_DEFINE", "DEVACCESS", "USER_ADDR", "PROFILE",
        "RSECTAB", "PRGN_CUST", "USOBT", "UST12", "SUSR", "USER_LOG",
        
        # Audit and Monitoring
        "RSAU_PERS", "RSAU_CONFIG", "RSAUFILES", "RSAU_VAL", "RSAUDIT_CASES", "RSAU_CONTROL",
        "RSECACTPRO", "RSECUDATA", "TPCF", "TST01",
        
        # Payment and Banking
        "REGUH", "PAYR", "BSEC", "FPLT", "T042Z", "BSEG", "TIBAN", "T012K", "T012T", "T001B",
        
        # Basis
        "TADIR", "TRDIR", "E071", "E070", "T000", "DDLOG", "TDEVC", "REPOS", "D010TAB",
        "D010INC", "NRIV", "TST01", "TMS_SRCSYS", "RSPARAM", "TSP01", "TPFET", "TPSRV",
        "TPSTAT", "VARI",
        
        # Financial
        "BKPF", "BSEG", "SKA1", "SKB1", "T030", "T001", "T001B", "T009", "T009B",
        "FAGLFLEXA", "FAGLFLEXT", "CSKS", "CSKB", "CEPC", "TKA01", "T003", "T012",
        "T012K", "BNKA", "REGUH", "PAYR", "TCURR", "TCURF", "TCURV", "T043T", "T042Y",
        
        # Jobs
        "TBTCO", "TBTCP", "TSDIR", "TBTCS", "BTCEVTJOB", "BTCJSTAT", "BTCSEVJOB", "BTCSYSPRD",
        
        # Materials Management
        "MCHA", "MCH1", "MSEG", "MKPF", "MBEW", "EKKO", "EKPO", "EINA", "EINE", "T156", "MARM",
        
        # Sales and Distribution
        "VBAK", "VBAP", "LIKP", "LIPS", "VBRK", "VBRP", "KNVV", "KONV", "A004", "A305",
        
        # Master Data
        "KNA1", "KNB1", "LFA1", "LFB1", "MARA", "MARC", "MVKE", "LFBK", "BUT000",
        
        # Workflow
        "SWWWIHEAD", "SWWUSERWI", "SWWCONT", "SWP_STEP", "SWWLOGHIST"
    }

def get_critical_field_patterns():
    """Return patterns for critical fields that should be monitored closely."""
    return {
        # Authentication and authorization fields
        r"(?i)PASS(WORD)?": "Password field",
        r"(?i)AUTH(ORIZATION)?": "Authorization field",
        r"(?i)ROLE": "Role assignment field",
        r"(?i)PERM(ISSION)?": "Permission field",
        r"(?i)ACCESS": "Access control field",
        r"(?i)KEY": "Security key field",
        r"(?i)CRED(ENTIAL)?": "Credential field",
        r"(?i)TOKEN": "Security token field",
        
        # Financial fields
        r"(?i)AMOUNT": "Financial amount field",
        r"(?i)CURR(ENCY)?": "Currency field",
        r"(?i)BANK": "Banking information field",
        r"(?i)ACCOUNT": "Account field",
        r"(?i)PAYMENT": "Payment field",
        r"(?i)CREDIT": "Credit field",
        r"(?i)TAX": "Tax field",
        
        # Master data fields
        r"(?i)VENDOR": "Vendor master data field",
        r"(?i)CUSTOMER": "Customer master data field",
        r"(?i)EMPLOYEE": "Employee data field",
        r"(?i)ADDRESS": "Address field",
        r"(?i)CONTACT": "Contact information field",
        
        # System configuration
        r"(?i)CONFIG": "Configuration field",
        r"(?i)SETTING": "System setting field",
        r"(?i)PARAM(ETER)?": "Parameter field",
        r"(?i)FLAG": "System flag field",
        r"(?i)MODE": "System mode field"
    }

def get_sensitive_tcodes():
    """Return a set of sensitive SAP transaction codes to monitor."""
    return {
        # Debugging
        "RSDEBUG", "/H", "/IWBEP/TRACES", "/IWFND/ERROR_LOG", "ST22", "ST05",
        
        # Audit and Compliance
        "SM19", "SM20", "RSAU_CONFIG", "GRC_RULESET", "GRC_RISK", "RMPS",
        "NWBC_AUDITING", "DPRM", "SARA",
        
        # Payment and Banking
        "F110", "FBPM", "FB70", "FCH5", "FC10", "FF67", "FF_5", "FCHI", "BPAY",
        
        # Table Maintenance
        "SE11", "SE14", "SE16N", "SM30", "SM31", "MASS",
        
        # Code Changes
        "SE38", "SE80", "SE24", "SE37", "SE09", "SE10", "SMOD", "CMOD",
        
        # Configuration
        "SPRO", "RZ10", "RZ11", "SCC4", "SCC5", "SCC7",
        
        # User Management
        "SU01", "SU10", "SU53", "SUIM", "PFCG", "SU25", "SU24", "SU56",
        
        # System Administration
        "SM49", "SM59", "SM69", "SM21", "SM37", "SM50", "SM51", "SM66",
        "RZ03", "RZ04", "RZ12", "RZ70", "STMS", "SPAM", "SAINT",
        
        # Sensitive Business Transactions
        "XK01", "XK02", "FK01", "FK02", "MK01", "MK02", "ME21N", "ME22N",
        "ME23N", "FB60", "FB65", "F-02", "F-01", "FBL1N", "FBL3N", "FBL5N"
    }

def assess_risk_legacy(correlated_data, unmatched_cdpos, unmatched_sm20):
    """
    Assess risk in the legacy correlation mode (direct SM20-CDPOS correlation).
    Returns a DataFrame with risk assessments.
    """
    log_message("Assessing risk in legacy correlation mode...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = correlated_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        critical_field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Assess risk based on sensitive tables
        if 'Table_Name' in risk_df.columns:
            risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_level'] = 'High'
            risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] = \
                risk_df.loc[risk_df['Table_Name'].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
        
        # Assess risk based on sensitive transaction codes
        # Check both SM20 and CDPOS transaction codes
        if SM20_TCODE_COL in risk_df.columns:
            risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df[SM20_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        if 'TCode_CD' in risk_df.columns:
            risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df['TCode_CD'].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        # Assess risk based on critical field patterns
        if CDPOS_FNAME_COL in risk_df.columns:
            for pattern, description in critical_field_patterns.items():
                mask = risk_df[CDPOS_FNAME_COL].str.contains(pattern, regex=True, na=False)
                risk_df.loc[mask, 'risk_level'] = 'High'
                risk_df.loc[mask, 'risk_factors'] = \
                    risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
            risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
        
        # Assess risk based on change indicator
        if 'Change_Indicator' in risk_df.columns:
            # Insert (I) and Delete (D) operations are higher risk than Update (U)
            risk_df.loc[risk_df['Change_Indicator'].isin(['I', 'D']), 'risk_level'] = 'High'
            risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] = \
                risk_df.loc[risk_df['Change_Indicator'] == 'I', 'risk_factors'] + 'Insert operation; '
            risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] = \
                risk_df.loc[risk_df['Change_Indicator'] == 'D', 'risk_factors'] + 'Delete operation; '
            
            # Updates are medium risk by default
            medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df['Change_Indicator'] == 'U')
            risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
            risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        return correlated_data

def assess_risk_session(session_data):
    """
    Assess risk in the session-based mode.
    Returns a DataFrame with risk assessments.
    """
    log_message("Assessing risk in session-based mode...")
    
    try:
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Get reference data for risk assessment
        sensitive_tables = get_sensitive_tables()
        sensitive_tcodes = get_sensitive_tcodes()
        critical_field_patterns = get_critical_field_patterns()
        
        # Initialize risk columns
        risk_df['risk_level'] = 'Low'
        risk_df['risk_factors'] = ''
        
        # Assess risk based on sensitive tables
        if SESSION_TABLE_COL in risk_df.columns:
            risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_TABLE_COL].isin(sensitive_tables), 'risk_factors'] + 'Sensitive table; '
        
        # Assess risk based on sensitive transaction codes
        if SESSION_TCODE_COL in risk_df.columns:
            risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_TCODE_COL].isin(sensitive_tcodes), 'risk_factors'] + 'Sensitive transaction code; '
        
        # Assess risk based on critical field patterns
        if SESSION_FIELD_COL in risk_df.columns:
            for pattern, description in critical_field_patterns.items():
                mask = risk_df[SESSION_FIELD_COL].str.contains(pattern, regex=True, na=False)
                risk_df.loc[mask, 'risk_level'] = 'High'
                risk_df.loc[mask, 'risk_factors'] = \
                    risk_df.loc[mask, 'risk_factors'] + f'Critical field ({description}); '
        
        # Assess risk based on display_but_changed flag
        if 'display_but_changed' in risk_df.columns:
            risk_df.loc[risk_df['display_but_changed'], 'risk_level'] = 'High'
            risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] = \
                risk_df.loc[risk_df['display_but_changed'], 'risk_factors'] + 'Display transaction with changes; '
        
        # Assess risk based on change indicator
        if SESSION_CHANGE_IND_COL in risk_df.columns:
            # Insert (I) and Delete (D) operations are higher risk than Update (U)
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL].isin(['I', 'D']), 'risk_level'] = 'High'
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'I', 'risk_factors'] + 'Insert operation; '
            risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] = \
                risk_df.loc[risk_df[SESSION_CHANGE_IND_COL] == 'D', 'risk_factors'] + 'Delete operation; '
            
            # Updates are medium risk by default
            medium_risk_mask = (risk_df['risk_level'] == 'Low') & (risk_df[SESSION_CHANGE_IND_COL] == 'U')
            risk_df.loc[medium_risk_mask, 'risk_level'] = 'Medium'
            risk_df.loc[medium_risk_mask, 'risk_factors'] = \
                risk_df.loc[medium_risk_mask, 'risk_factors'] + 'Update operation; '
        
        # Count risk levels
        high_risk_count = len(risk_df[risk_df['risk_level'] == 'High'])
        medium_risk_count = len(risk_df[risk_df['risk_level'] == 'Medium'])
        low_risk_count = len(risk_df[risk_df['risk_level'] == 'Low'])
        
        log_message(f"Risk assessment complete. High: {high_risk_count}, Medium: {medium_risk_count}, Low: {low_risk_count}")
        
        return risk_df
    
    except Exception as e:
        log_message(f"Error during risk assessment: {str(e)}", "ERROR")
        return session_data

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

if __name__ == "__main__":
    # Add a banner
    banner = "\n" + "="*80 + "\n"
    banner += " SAP AUDIT TOOL v{} ".format(VERSION).center(80, "*") + "\n"
    banner += " Enhanced Security Analysis for SAP Logs ".center(80) + "\n"
    banner += "="*80 + "\n"
    print(banner)
    
    main()
