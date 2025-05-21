#!/usr/bin/env python3
"""
SAP Audit Tool - Risk Assessment Module

This module contains the core risk assessment functionality, orchestrating the
various risk detection methods and implementing the primary risk assessment logic.
It uses a class-based approach to organize risk assessment functions into logical groups.

Key functionality:
1. Table-based risk assessment
2. Transaction code-based risk assessment
3. Field pattern-based risk assessment
4. Change indicator-based risk assessment
5. Debug pattern detection and correlation
6. SAP event code risk assessment
7. Default risk classification for low-risk items

Usage:
    from sap_audit_risk import RiskAssessor
    
    # Create a risk assessor instance
    risk_assessor = RiskAssessor()
    
    # Process a session dataframe
    enhanced_df = risk_assessor.assess_risk(session_df)
"""

import pandas as pd

# Import configuration
from sap_audit_config import COLUMNS, RISK

# Import utility functions
from sap_audit_utils import (
    log_message, log_section, log_error, log_stats, handle_exception,
    format_field_info, format_tcode_info, format_table_info, format_event_code_info,
    clean_whitespace, standardize_column_values, validate_required_columns
)

# Import reference data
from sap_audit_reference_data import (
    get_sensitive_tables, get_sensitive_table_descriptions,
    get_common_table_descriptions, get_sensitive_tcodes,
    get_sensitive_tcode_descriptions, get_common_tcode_descriptions,
    get_common_field_descriptions, get_critical_field_patterns,
    get_critical_field_pattern_descriptions, get_sap_event_code_classifications,
    get_sap_event_code_descriptions
)

# Import detector functions
from sap_audit_detectors import (
    custom_field_risk_assessment, detect_field_patterns,
    detect_debug_patterns, detect_debug_with_changes,
    classify_activity_type, detect_event_code_risk, analyze_event_details,
    detect_debug_message_codes, detect_authorization_bypass, detect_inventory_manipulation,
    INVENTORY_SENSITIVE_TABLES, INVENTORY_CRITICAL_FIELDS
)

class RiskAssessor:
    """
    Main class for SAP risk assessment.
    
    This class provides methods to assess various types of risks in SAP audit data,
    including sensitive table access, transaction code usage, field modifications,
    debugging activities, and more.
    """
    
    def __init__(self, config=None):
        """
        Initialize risk assessor with configuration.
        
        Args:
            config (dict, optional): Risk configuration override. If None, use default config.
        """
        self.config = config or RISK
        self.column_map = COLUMNS["session"]
        
        # Set up column names from config/column map
        self.col_names = {
            "table": self.column_map.get("table", "Table"),
            "tcode": self.column_map.get("tcode", "TCode"),
            "field": self.column_map.get("field", "Field"),
            "change_ind": self.column_map.get("change_indicator", "Change_Indicator"),
            "event": self.column_map.get("event", "Event"),
            "risk_level": self.config["column_names"].get("risk_level", "risk_level"),
            "sap_risk_level": self.config["column_names"].get("sap_risk_level", "sap_risk_level"),
            "risk_description": self.config["column_names"].get("risk_description", "risk_description"),
            "activity_type": self.config["column_names"].get("activity_type", "activity_type")
        }
        
        # Get risk levels from config
        self.risk_levels = self.config["levels"]
        self.sap_risk_levels = self.config["sap_levels"]
        
        # Load reference data (lazy loading to improve startup performance)
        self._sensitive_tables = None
        self._sensitive_table_descriptions = None
        self._common_table_descriptions = None
        self._sensitive_tcodes = None
        self._sensitive_tcode_descriptions = None
        self._common_tcode_descriptions = None
        self._common_field_descriptions = None
        self._field_patterns = None
        self._field_descriptions = None
        self._event_code_classifications = None
        self._event_code_descriptions = None
    
    @property
    def sensitive_tables(self):
        """Lazy-load sensitive tables list."""
        if self._sensitive_tables is None:
            self._sensitive_tables = get_sensitive_tables()
        return self._sensitive_tables
    
    @property
    def sensitive_table_descriptions(self):
        """Lazy-load sensitive table descriptions."""
        if self._sensitive_table_descriptions is None:
            self._sensitive_table_descriptions = get_sensitive_table_descriptions()
        return self._sensitive_table_descriptions
    
    @property
    def common_table_descriptions(self):
        """Lazy-load common table descriptions."""
        if self._common_table_descriptions is None:
            self._common_table_descriptions = get_common_table_descriptions()
        return self._common_table_descriptions
    
    @property
    def sensitive_tcodes(self):
        """Lazy-load sensitive transaction codes."""
        if self._sensitive_tcodes is None:
            self._sensitive_tcodes = get_sensitive_tcodes()
        return self._sensitive_tcodes
    
    @property
    def sensitive_tcode_descriptions(self):
        """Lazy-load sensitive transaction code descriptions."""
        if self._sensitive_tcode_descriptions is None:
            self._sensitive_tcode_descriptions = get_sensitive_tcode_descriptions()
        return self._sensitive_tcode_descriptions
    
    @property
    def common_tcode_descriptions(self):
        """Lazy-load common transaction code descriptions."""
        if self._common_tcode_descriptions is None:
            self._common_tcode_descriptions = get_common_tcode_descriptions()
        return self._common_tcode_descriptions
    
    @property
    def common_field_descriptions(self):
        """Lazy-load common field descriptions."""
        if self._common_field_descriptions is None:
            self._common_field_descriptions = get_common_field_descriptions()
        return self._common_field_descriptions
    
    @property
    def field_patterns(self):
        """Lazy-load critical field patterns."""
        if self._field_patterns is None:
            self._field_patterns = get_critical_field_patterns()
        return self._field_patterns
    
    @property
    def field_descriptions(self):
        """Lazy-load critical field pattern descriptions."""
        if self._field_descriptions is None:
            self._field_descriptions = get_critical_field_pattern_descriptions()
        return self._field_descriptions
    
    @property
    def event_code_classifications(self):
        """Lazy-load event code classifications."""
        if self._event_code_classifications is None:
            self._event_code_classifications = get_sap_event_code_classifications()
        return self._event_code_classifications
    
    @property
    def event_code_descriptions(self):
        """Lazy-load event code descriptions."""
        if self._event_code_descriptions is None:
            self._event_code_descriptions = get_sap_event_code_descriptions()
        return self._event_code_descriptions
    
    @handle_exception
    def assess_risk(self, session_data):
        """
        Main risk assessment function. This orchestrates the various risk assessment
        methods and combines their results.
        
        Args:
            session_data: DataFrame containing session data
            
        Returns:
            DataFrame with risk assessments applied
        """
        log_section("Starting Risk Assessment")
        
        # Input validation
        if session_data is None or session_data.empty:
            log_message("No session data provided for risk assessment", "ERROR")
            return pd.DataFrame()
            
        # Validate required columns
        required_columns = [self.column_map["user"], self.column_map["datetime"]]
        is_valid, missing_cols = validate_required_columns(
            session_data, required_columns, "Session Timeline"
        )
        
        if not is_valid:
            log_message(f"Risk assessment requires {', '.join(missing_cols)} columns", "ERROR")
            return session_data
        
        # Create a copy to avoid SettingWithCopyWarning
        risk_df = session_data.copy()
        
        # Process risk assessment steps
        try:
            # Data preparation and initialization
            risk_df = self._prepare_risk_assessment(risk_df)
            
            # Apply different risk assessment methods
            risk_df = self._assess_table_risks(risk_df)
            risk_df = self._assess_tcode_risks(risk_df)
            risk_df = self._assess_field_risks(risk_df)
            risk_df = self._assess_change_indicator_risks(risk_df)
            risk_df = self._assess_display_but_changed_risks(risk_df)
            risk_df = self._assess_debug_risks(risk_df)
            risk_df = self._assess_event_code_risks(risk_df)
            
            # Add default descriptions for remaining low-risk items
            risk_df = self._add_default_risk_factors(risk_df)
            
            # Summarize risk assessment results
            self._summarize_risk_assessment(risk_df)
            
            return risk_df
        
        except Exception as e:
            log_error(e, "Error during risk assessment")
            # Return original data if assessment fails
            return session_data
    
    def _prepare_risk_assessment(self, risk_df):
        """
        Prepare data frame for risk assessment by cleaning data and initializing
        risk columns.
        
        Args:
            risk_df: DataFrame to prepare
            
        Returns:
            Prepared DataFrame
        """
        log_message("Preparing data for risk assessment...")
        
        # Minimal cleaning for defensive programming
        for col in [
            self.col_names["table"], 
            self.col_names["tcode"], 
            self.col_names["field"], 
            self.col_names["change_ind"]
        ]:
            if col in risk_df.columns and risk_df[col].dtype == 'object':
                # Only clean if we see excessive whitespace
                if (risk_df[col].astype(str).str.strip() != risk_df[col]).any():
                    log_message(f"Found whitespace in {col} column. Performing defensive cleaning.", "WARNING")
                    risk_df[col] = risk_df[col].astype(str).str.strip()
        
        # Initialize risk columns
        risk_df[self.col_names["risk_level"]] = self.risk_levels["low"]
        risk_df[self.col_names["sap_risk_level"]] = self.sap_risk_levels["non_critical"]
        risk_df[self.col_names["risk_description"]] = ""
        
        # Add activity type classification if not already present
        if self.col_names["activity_type"] not in risk_df.columns:
            risk_df[self.col_names["activity_type"]] = risk_df.apply(classify_activity_type, axis=1)
        
        return risk_df
    
    @handle_exception
    def _assess_table_risks(self, risk_df):
        """
        Assess risks based on table access.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with table risk assessments
        """
        table_col = self.col_names["table"]
        field_col = self.col_names["field"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Skip if table column not present
        if table_col not in risk_df.columns:
            log_message(f"Skipping table-based risk assessment - {table_col} column not found", "WARNING")
            return risk_df
            
        log_message("Assessing table-based risks...")
        
        # Count records before assessment
        initial_count = len(risk_df)
        high_risk_count = 0
        
        for table in self.sensitive_tables:
            # Case-insensitive match
            table_mask = risk_df[table_col].str.upper() == table.upper()
            match_count = sum(table_mask)
            
            if match_count > 0:
                risk_df.loc[table_mask, risk_level_col] = self.risk_levels["high"]
                high_risk_count += match_count
                
                # Get table description
                description = self.sensitive_table_descriptions.get(
                    table, f"Sensitive table '{table}' - Contains critical system data"
                )
                
                # Update risk description with table info and field info if available
                risk_df.loc[table_mask, risk_desc_col] = risk_df.loc[table_mask].apply(
                    lambda row: f"{description} (Table: {table}" + 
                               (f", Field: {format_field_info(row[field_col], self.common_field_descriptions)}" 
                                if pd.notna(row[field_col]) and row[field_col].strip() != "" else "") + ")",
                    axis=1)
        
        log_message(f"Identified {high_risk_count} high-risk table accesses")
        return risk_df
    
    @handle_exception
    def _assess_tcode_risks(self, risk_df):
        """
        Assess risks based on transaction code usage.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with tcode risk assessments
        """
        tcode_col = self.col_names["tcode"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Skip if tcode column not present
        if tcode_col not in risk_df.columns:
            log_message(f"Skipping tcode-based risk assessment - {tcode_col} column not found", "WARNING")
            return risk_df
            
        log_message("Assessing transaction code-based risks...")
        
        # Count records before assessment
        high_risk_count = 0
        
        for tcode in self.sensitive_tcodes:
            # Case-insensitive match
            tcode_mask = risk_df[tcode_col].str.upper() == tcode.upper()
            match_count = sum(tcode_mask)
            
            if match_count > 0:
                risk_df.loc[tcode_mask, risk_level_col] = self.risk_levels["high"]
                high_risk_count += match_count
                
                # Get tcode description
                description = self.sensitive_tcode_descriptions.get(
                    tcode, f"Sensitive transaction '{tcode}' - Privileged system function"
                )
                
                # Only update risk description if not already set by table assessment
                empty_factors_mask = tcode_mask & (risk_df[risk_desc_col] == '')
                risk_df.loc[empty_factors_mask, risk_desc_col] = f"{description} (TCode: {tcode})"
        
        log_message(f"Identified {high_risk_count} high-risk transaction code usages")
        return risk_df
    
    @handle_exception
    def _assess_field_risks(self, risk_df):
        """
        Assess risks based on field patterns.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with field risk assessments
        """
        field_col = self.col_names["field"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Skip if field column not present
        if field_col not in risk_df.columns:
            log_message(f"Skipping field-based risk assessment - {field_col} column not found", "WARNING")
            return risk_df
            
        log_message("Assessing field pattern-based risks...")
        
        # Count records before assessment
        high_risk_count = 0
        
        # Handle null values properly
        adjusted_fields = risk_df[field_col].fillna('')
        
        # Apply custom field assessment for special cases
        for idx, row in risk_df.iterrows():
            field_value = row[field_col] if pd.notna(row[field_col]) else ""
            is_high_risk, risk_desc = custom_field_risk_assessment(field_value)
            
            if is_high_risk and risk_desc:
                risk_df.loc[idx, risk_level_col] = self.risk_levels["high"]
                high_risk_count += 1
                
                # Only update if risk description not already set
                if risk_df.loc[idx, risk_desc_col] == '':
                    # Add field description if available
                    field_desc = self.common_field_descriptions.get(field_value.upper(), "")
                    field_info = f"{field_value}"
                    if field_desc:
                        field_info = f"{field_value} ({field_desc.split(' - ')[0]})"
                    
                    risk_df.loc[idx, risk_desc_col] = f"{risk_desc} (Field: {field_info})"
        
        # Skip specific fields that should be excluded
        exclude_fields = ["KEY", "SPERM", "SPERQ", "QUAN"]
        exclude_mask = ~adjusted_fields.str.upper().isin([f.upper() for f in exclude_fields])
        
        # Apply pattern matching for remaining fields
        for pattern, basic_desc in self.field_patterns.items():
            # Use word-bounded patterns to avoid false matches, and skip excluded fields
            pattern_mask = adjusted_fields.str.contains(pattern, regex=True, na=False) & exclude_mask
            match_count = sum(pattern_mask)
            
            if match_count > 0:
                risk_df.loc[pattern_mask, risk_level_col] = self.risk_levels["high"]
                high_risk_count += match_count
                
                description = self.field_descriptions.get(pattern, f"Critical field ({basic_desc}) - Contains sensitive data")
                
                # Only update risk description if not already set by previous assessments
                empty_factors_mask = pattern_mask & (risk_df[risk_desc_col] == '')
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"{description} (Field: {format_field_info(x[field_col], self.common_field_descriptions)})", 
                    axis=1)
        
        log_message(f"Identified {high_risk_count} high-risk field pattern matches")
        return risk_df
    
    @handle_exception
    def _assess_change_indicator_risks(self, risk_df):
        """
        Assess risks based on change indicators (Insert, Update, Delete).
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with change indicator risk assessments
        """
        change_ind_col = self.col_names["change_ind"]
        table_col = self.col_names["table"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Skip if change indicator column not present
        if change_ind_col not in risk_df.columns:
            log_message(f"Skipping change indicator risk assessment - {change_ind_col} column not found", "WARNING")
            return risk_df
            
        log_message("Assessing change indicator-based risks...")
        
        # Count for statistics
        insert_count = 0
        update_count = 0
        delete_count = 0
        
        # Insert (I) operations
        insert_mask = risk_df[change_ind_col].str.upper() == 'I'
        insert_count = sum(insert_mask)
        
        if insert_count > 0:
            risk_df.loc[insert_mask, risk_level_col] = self.risk_levels["high"]
            empty_factors_mask = insert_mask & (risk_df[risk_desc_col] == '')
            
            if table_col in risk_df.columns:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"New data creation: User added new information to the system database. [Technical: Insert operation - New record created in {format_table_info(x[table_col], self.common_table_descriptions, self.sensitive_table_descriptions)} table]",
                    axis=1)
            else:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"New data creation: User added new information to the system database. [Technical: Insert operation (Change: {x[change_ind_col]}) - New record created]", axis=1)
        
        # Delete (D) operations
        delete_mask = risk_df[change_ind_col].str.upper() == 'D'
        delete_count = sum(delete_mask)
        
        if delete_count > 0:
            risk_df.loc[delete_mask, risk_level_col] = self.risk_levels["high"]
            empty_factors_mask = delete_mask & (risk_df[risk_desc_col] == '')
            
            if table_col in risk_df.columns:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Data deletion: User permanently removed information from the system - this deserves review to ensure the deletion was authorized. [Technical: Delete operation - Record removed from {format_table_info(x[table_col], self.common_table_descriptions, self.sensitive_table_descriptions)} table]",
                    axis=1)
            else:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Data deletion: User permanently removed information from the system - this deserves review to ensure the deletion was authorized. [Technical: Delete operation (Change: {x[change_ind_col]}) - Record removed]", axis=1)
        
        # Updates (U) are medium risk by default
        update_mask = (risk_df[risk_level_col] == self.risk_levels["low"]) & (risk_df[change_ind_col].str.upper() == 'U')
        update_count = sum(update_mask)
        
        if update_count > 0:
            risk_df.loc[update_mask, risk_level_col] = self.risk_levels["medium"]
            empty_factors_mask = update_mask & (risk_df[risk_desc_col] == '')
            
            if table_col in risk_df.columns:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Data modification: User changed existing information in the system - changes to existing data should be reviewed for appropriateness. [Technical: Update operation - Existing record modified in {format_table_info(x[table_col], self.common_table_descriptions, self.sensitive_table_descriptions)} table]",
                    axis=1)
            else:
                risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                    lambda x: f"Data modification: User changed existing information in the system - changes to existing data should be reviewed for appropriateness. [Technical: Update operation (Change: {x[change_ind_col]}) - Existing record modified]", axis=1)
        
        log_message(f"Change indicator risks: {insert_count} inserts, {delete_count} deletes, {update_count} updates")
        return risk_df
    
    @handle_exception
    def _assess_display_but_changed_risks(self, risk_df):
        """
        Assess risks based on display-but-changed flags.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with display-but-changed risk assessments
        """
        tcode_col = self.col_names["tcode"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Skip if display_but_changed column not present
        if 'display_but_changed' not in risk_df.columns:
            return risk_df
            
        log_message("Assessing display-but-changed flags...")
        
        # Count for statistics
        affected_count = 0
        
        mask = risk_df['display_but_changed']
        affected_count = sum(mask)
        
        if affected_count > 0:
            risk_df.loc[mask, risk_level_col] = self.risk_levels["high"]
            empty_factors_mask = mask & (risk_df[risk_desc_col] == '')
            
            risk_df.loc[empty_factors_mask, risk_desc_col] = risk_df.loc[empty_factors_mask].apply(
                lambda x: f"Unusual view transaction with data changes: Activity appeared as read-only but also made data modifications - this inconsistency requires investigation as it could indicate inappropriate data manipulation. [Technical: Display transaction with changes (TCode: {format_tcode_info(x[tcode_col], self.common_tcode_descriptions, self.sensitive_tcode_descriptions)}) - Activity logged as view-only but includes data modifications]",
                axis=1)
        
        if affected_count > 0:
            log_message(f"Identified {affected_count} display-but-changed risk indicators", "WARNING")
            
        return risk_df
    
    @handle_exception
    def _assess_debug_risks(self, risk_df):
        """
        Assess risks related to debugging activities.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with debug risk assessments
        """
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        
        # Check if required fields are present for debugging detection
        debug_var_fields_present = all(field in risk_df.columns for field in ['Variable_First', 'Variable_2', 'Variable_Data'])
        message_id_present = 'Message_ID' in risk_df.columns
        
        if not (debug_var_fields_present or message_id_present):
            log_message("Skipping debugging pattern detection - required fields not present in dataset", "INFO")
            return risk_df
            
        log_message("Applying enhanced debugging pattern detection...")
        
        # Count for statistics
        debug_pattern_count = 0
        debug_message_count = 0
        
        # 1. Apply Variable-based debugging detection (legacy approach)
        if debug_var_fields_present:
            for idx, row in risk_df.iterrows():
                debug_risk_level, debug_risk_factors = detect_debug_patterns(row)
                
                if debug_risk_level and debug_risk_factors:
                    debug_pattern_count += 1
                    
                    # Override risk level if debug risk is higher
                    current_level = risk_df.loc[idx, risk_level_col]
                    if (debug_risk_level == 'Critical' or 
                        (debug_risk_level == 'High' and current_level != 'Critical') or
                        (debug_risk_level == 'Medium' and current_level not in ['Critical', 'High'])):
                        risk_df.loc[idx, risk_level_col] = debug_risk_level
                    
                    # Add debug risk factors to existing ones
                    current_factors = risk_df.loc[idx, risk_desc_col]
                    risk_df.loc[idx, risk_desc_col] = current_factors + "; " + "; ".join(debug_risk_factors) if current_factors else "; ".join(debug_risk_factors)
        
        # 2. Apply Message Code-based debugging detection (new approach)
        if message_id_present:
            log_message("Applying message code-based debugging detection...")
            
            for idx, row in risk_df.iterrows():
                detected, risk_level, risk_description = detect_debug_message_codes(row)
                
                if detected:
                    debug_message_count += 1
                    # Override risk level if higher
                    current_level = risk_df.loc[idx, risk_level_col]
                    if (risk_level == 'Critical' or 
                        (risk_level == 'High' and current_level != 'Critical') or
                        (risk_level == 'Medium' and current_level not in ['Critical', 'High'])):
                        risk_df.loc[idx, risk_level_col] = risk_level
                    
                    # Add message code risk description
                    current_factors = risk_df.loc[idx, risk_desc_col]
                    if current_factors and current_factors.strip():
                        risk_df.loc[idx, risk_desc_col] = current_factors + "; " + risk_description
                    else:
                        risk_df.loc[idx, risk_desc_col] = risk_description
            
            if debug_message_count > 0:
                log_message(f"Found {debug_message_count} debug events based on message codes", "WARNING")
        
        # 3. Session-based pattern detection (analyzes multiple events together)
        if 'Session ID with Date' in risk_df.columns:
            log_message("Analyzing session-based debugging patterns...")
            
            auth_bypass_count = 0
            inv_manip_count = 0
            
            # Group by session ID to analyze patterns within sessions
            for session_id, session_group in risk_df.groupby('Session ID with Date'):
                # Check for authorization bypass pattern
                auth_bypass_detected, auth_bypass_risk, auth_bypass_factors = detect_authorization_bypass(session_group)
                
                if auth_bypass_detected:
                    auth_bypass_count += 1
                    log_message(f"Found authorization bypass pattern in session {session_id}", "WARNING")
                    
                    # Apply to all events in the session
                    for idx in session_group.index:
                        # Only upgrade risk level (never downgrade)
                        if auth_bypass_risk == 'Critical' or risk_df.loc[idx, risk_level_col] != 'Critical':
                            risk_df.loc[idx, risk_level_col] = auth_bypass_risk
                        
                        # Add risk description
                        current_factors = risk_df.loc[idx, risk_desc_col]
                        if current_factors and current_factors.strip():
                            risk_df.loc[idx, risk_desc_col] = current_factors + "; " + "; ".join(auth_bypass_factors)
                        else:
                            risk_df.loc[idx, risk_desc_col] = "; ".join(auth_bypass_factors)
                
                # Check for inventory manipulation with debugging
                inv_manip_detected, inv_manip_risk, inv_manip_factors = detect_inventory_manipulation(
                    session_group, INVENTORY_SENSITIVE_TABLES)
                
                if inv_manip_detected:
                    inv_manip_count += 1
                    log_message(f"Found inventory manipulation pattern in session {session_id}", "WARNING")
                    # Apply to all events in the session
                    for idx in session_group.index:
                        # Only upgrade risk level (never downgrade)
                        if inv_manip_risk == 'Critical' or risk_df.loc[idx, risk_level_col] != 'Critical':
                            risk_df.loc[idx, risk_level_col] = inv_manip_risk
                        
                        # Add risk description
                        current_factors = risk_df.loc[idx, risk_desc_col]
                        if current_factors and current_factors.strip():
                            risk_df.loc[idx, risk_desc_col] = current_factors + "; " + "; ".join(inv_manip_factors)
                        else:
                            risk_df.loc[idx, risk_desc_col] = "; ".join(inv_manip_factors)
            
            # Legacy debug + changes detection
            log_message("Analyzing debug activity correlation with data changes...")
            risk_df = detect_debug_with_changes(risk_df)
            
            # Statistics
            if auth_bypass_count > 0:
                log_message(f"Found {auth_bypass_count} authorization bypass patterns", "WARNING")
            
            if inv_manip_count > 0:
                log_message(f"Found {inv_manip_count} inventory manipulation patterns", "WARNING")
            
            # Count critical risk after debugging analysis
            critical_risk_count = len(risk_df[risk_df[risk_level_col] == self.risk_levels["critical"]])
            if critical_risk_count > 0:
                log_message(f"Found {critical_risk_count} critical risk events from debugging pattern analysis", "WARNING")
        
        log_message(f"Debug pattern detection completed with {debug_pattern_count} variable-based patterns and {debug_message_count} message-based patterns")
        return risk_df
    
    @handle_exception
    def _assess_event_code_risks(self, risk_df):
        """
        Assess risks based on SAP event codes.
        
        Args:
            risk_df: DataFrame to assess
            
        Returns:
            DataFrame with event code risk assessments
        """
        event_col = self.col_names["event"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        sap_risk_level_col = self.col_names["sap_risk_level"]
        
        # Skip if event column not present
        if event_col not in risk_df.columns:
            log_message(f"Skipping event code risk assessment - {event_col} column not found", "WARNING")
            return risk_df
            
        log_message("Applying SAP event code risk analysis...")
        
        # Count for statistics
        high_risk_count = 0
        medium_risk_count = 0
        
        # Apply event code classification
        for idx, row in risk_df.iterrows():
            event_code = str(row[event_col]) if pd.notna(row[event_col]) else ""
            event_risk_level, event_risk_desc = detect_event_code_risk(event_code, self.event_code_classifications)
            
            if event_risk_level and event_risk_desc:
                # Map SAP criticality to our risk levels
                if event_risk_level == 'High':
                    if risk_df.loc[idx, risk_level_col] != self.risk_levels["critical"]:
                        risk_df.loc[idx, risk_level_col] = self.risk_levels["high"]
                        high_risk_count += 1
                elif event_risk_level == 'Medium' and risk_df.loc[idx, risk_level_col] not in [self.risk_levels["critical"], self.risk_levels["high"]]:
                    risk_df.loc[idx, risk_level_col] = self.risk_levels["medium"]
                    medium_risk_count += 1
                
                # Add SAP event classification to risk factors
                event_details = analyze_event_details(row, self.event_code_descriptions)
                event_desc = self.event_code_descriptions.get(event_code.strip().upper(), "")
                
                factor = f"SAP Event: {format_event_code_info(event_code, self.event_code_descriptions)}"
                if event_details:
                    factor += f" - {event_details}"
                
                # Add to existing risk description if present
                current_factors = risk_df.loc[idx, risk_desc_col]
                if current_factors and current_factors.strip():
                    risk_df.loc[idx, risk_desc_col] = current_factors + "; " + factor
                else:
                    risk_df.loc[idx, risk_desc_col] = factor
                    
                # Set SAP risk level based on event classification
                if event_risk_level == 'High':
                    risk_df.loc[idx, sap_risk_level_col] = self.sap_risk_levels["critical"]
                elif event_risk_level == 'Medium':
                    risk_df.loc[idx, sap_risk_level_col] = self.sap_risk_levels["important"]
                else:
                    risk_df.loc[idx, sap_risk_level_col] = self.sap_risk_levels["non_critical"]
        
        log_message(f"Event code risks: {high_risk_count} high, {medium_risk_count} medium risk events")
        return risk_df
    
    @handle_exception
    def _add_default_risk_factors(self, risk_df):
        """
        Add default risk descriptions to low-risk items.
        
        Args:
            risk_df: DataFrame to update
            
        Returns:
            DataFrame with default risk descriptions added
        """
        tcode_col = self.col_names["tcode"] 
        table_col = self.col_names["table"]
        risk_level_col = self.col_names["risk_level"]
        risk_desc_col = self.col_names["risk_description"]
        activity_type_col = self.col_names["activity_type"]
        
        log_message("Adding default risk descriptions for remaining low-risk items...")
        
        # Count items needing default descriptions
        low_risk_no_factor_mask = (risk_df[risk_level_col] == self.risk_levels["low"]) & (risk_df[risk_desc_col] == '')
        low_risk_count = sum(low_risk_no_factor_mask)
        
        if low_risk_count > 0:
            log_message(f"Adding risk descriptions to {low_risk_count} low-risk items")
            
            # Use activity_type to categorize low-risk items
            for idx, row in risk_df[low_risk_no_factor_mask].iterrows():
                activity = row.get(activity_type_col, 'Unknown')
                tcode = row.get(tcode_col, 'Unknown') if pd.notna(row.get(tcode_col)) else 'Unknown'
                table = row.get(table_col, '') if pd.notna(row.get(table_col)) else ''
                
                # Get descriptions if available
                tcode_description = ""
                if tcode != 'Unknown' and tcode.strip() != "":
                    tcode_description = self.common_tcode_descriptions.get(tcode.upper(), self.sensitive_tcode_descriptions.get(tcode.upper(), ""))
                    if tcode_description:
                        tcode_description = f" ({tcode_description.split(' - ')[0]})"
                
                table_description = ""
                if table and pd.notna(table) and table.strip() != '' and table != "nan":
                    table_description = self.common_table_descriptions.get(table.upper(), self.sensitive_table_descriptions.get(table.upper(), ""))
                    if table_description:
                        table_description = f" ({table_description.split(' - ')[0]})"
                
                if activity == 'View':
                    risk_df.loc[idx, risk_desc_col] = f"Information viewing activity: User only viewed data without making changes - standard access for reporting purposes. [Technical: Standard view activity (TCode: {tcode}{tcode_description}) - Read-only access to system data]"
                elif activity == 'Financial':
                    risk_df.loc[idx, risk_desc_col] = f"Regular financial transaction: Standard accounting activity that is part of normal business operations. [Technical: Standard financial transaction (TCode: {tcode}{tcode_description}) - Normal business process]"
                elif activity == 'Material Management':
                    risk_df.loc[idx, risk_desc_col] = f"Inventory management: Routine activity to manage inventory, materials, or purchasing - part of standard operations. [Technical: Standard material management activity (TCode: {tcode}{tcode_description}) - Normal inventory process]"
                elif activity == 'Sales':
                    risk_df.loc[idx, risk_desc_col] = f"Sales process: Standard sales or customer-related activity that is part of normal business operations. [Technical: Standard sales activity (TCode: {tcode}{tcode_description}) - Normal business process]"
                elif activity == 'Other' and table and pd.notna(table) and table.strip() != '':
                    if pd.notna(table) and table != "nan":
                        risk_df.loc[idx, risk_desc_col] = f"Regular data access: User accessed non-sensitive business data tables - normal system usage. [Technical: Non-sensitive table access (Table: {table}{table_description}) - Contains non-sensitive data]"
                    else:
                        tcode_str = "" if tcode == "Unknown" or tcode.strip() == "" else f" (TCode: {tcode}{tcode_description})"
                        risk_df.loc[idx, risk_desc_col] = f"Standard system usage: Routine system access without any data modifications. [Technical: Standard system access{tcode_str} - No table modifications detected]"
                elif tcode != 'Unknown' and tcode.strip() != "":
                    risk_df.loc[idx, risk_desc_col] = f"Standard business function: Regular transaction used for routine business activities. [Technical: Standard transaction (TCode: {tcode}{tcode_description}) - Routine business function]"
                else:
                    risk_df.loc[idx, risk_desc_col] = f"Low-risk system activity: Regular system usage that doesn't involve sensitive data or system changes. [Technical: Low risk activity - No sensitive data or system changes involved]"
        
        return risk_df
    
    def _summarize_risk_assessment(self, risk_df):
        """
        Summarize risk assessment results and log statistics.
        
        Args:
            risk_df: DataFrame with risk assessments
            
        Returns:
            None (outputs to logs)
        """
        risk_level_col = self.col_names["risk_level"]
        
        # Count risk levels
        critical_risk_count = len(risk_df[risk_df[risk_level_col] == self.risk_levels["critical"]])
        high_risk_count = len(risk_df[risk_df[risk_level_col] == self.risk_levels["high"]])
        medium_risk_count = len(risk_df[risk_df[risk_level_col] == self.risk_levels["medium"]])
        low_risk_count = len(risk_df[risk_df[risk_level_col] == self.risk_levels["low"]])
        
        total_count = len(risk_df)
        
        # Calculate percentages
        if total_count > 0:
            critical_pct = 100.0 * critical_risk_count / total_count
            high_pct = 100.0 * high_risk_count / total_count
            medium_pct = 100.0 * medium_risk_count / total_count
            low_pct = 100.0 * low_risk_count / total_count
        else:
            critical_pct = high_pct = medium_pct = low_pct = 0.0
        
        # Log statistics
        log_section("Risk Assessment Summary")
        log_message(f"Total records assessed: {total_count}")
        log_stats("Risk Level Distribution", {
            "Critical": f"{critical_risk_count} ({critical_pct:.1f}%)",
            "High": f"{high_risk_count} ({high_pct:.1f}%)",
            "Medium": f"{medium_risk_count} ({medium_pct:.1f}%)",
            "Low": f"{low_risk_count} ({low_pct:.1f}%)"
        })
        
        # Warning if critical risks found
        if critical_risk_count > 0:
            log_message(f"FOUND {critical_risk_count} CRITICAL RISK EVENTS - Immediate investigation recommended", "WARNING")
        elif high_risk_count > 0:
            log_message(f"Found {high_risk_count} high risk events - Review recommended", "WARNING")
        
        log_message("Risk assessment completed successfully")


if __name__ == "__main__":
    """
    Simple test if run as main script.
    """
    print("SAP Audit Risk Assessment Module")
    print("Run with a session DataFrame to perform risk assessment.")
    print("Example:")
    print("  from sap_audit_risk import RiskAssessor")
    print("  risk_assessor = RiskAssessor()")
    print("  enhanced_df = risk_assessor.assess_risk(session_df)")
