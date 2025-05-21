#!/usr/bin/env python3
"""
SAP Audit Tool - SysAid Integration Module

This module provides functionality to integrate SysAid ticket information with SAP audit data.
It implements the Strategy pattern for different SysAid data sources and includes
robust error handling and caching mechanisms.

Key features:
- SysAidIntegrator class with clear responsibilities
- Strategy pattern implementation for different data sources
- Robust error handling and retry mechanisms for API calls
- Validation for SysAid data consistency
- Improved caching for performance optimization
- Standardized error messages and logging
"""

import os
import pandas as pd
import json
import re
import time
from datetime import datetime
from abc import ABC, abstractmethod
import requests
from typing import Dict, List, Optional, Union, Any, Tuple

# Import configuration and utilities
from sap_audit_config import PATHS, SYSAID
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
            log_message(f"Record counts: {source_type} - {file_name}: {original_count} → {final_count}")
        
        def update_timeline_count(self, total_records, source_counts=None):
            pass
        
        def get_counts_for_report(self):
            return {"completeness_score": 0, "source_files": []}
    
    record_counter = RecordCounter()

# Constants
SYSAID_TICKET_COL_OPTIONS = ['Ticket', 'Ticket #', 'TicketID', 'ID', 'ticket', 'SysAid #', 'SYSAID#', 'SYSAID']
SESSION_COL_OPTIONS = ['Session ID', 'SESSION ID', 'SessionID', 'Session', 'Session ID with Date']
SAP_SYSAID_COL_OPTIONS = ['SYSAID#', 'SysAid#', 'SYSAID', 'SysAid', 'Ticket', 'Ticket #']


class SysAidDataStrategy(ABC):
    """
    Abstract base class for SysAid data loading strategies.
    
    Implementations handle different ways of loading SysAid data,
    such as from files or APIs.
    """
    
    def __init__(self, config=None):
        """
        Initialize with optional custom configuration.
        
        Args:
            config: Dictionary with configuration overrides
        """
        self.config = config or SYSAID
        self.paths = PATHS
    
    @abstractmethod
    def load_data(self):
        """
        Load SysAid ticket information.
        
        Returns:
            DataFrame with SysAid data, or None if loading fails
        """
        pass
    
    def standardize_sysaid(self, value):
        """
        Standardize SysAid ticket number format.
        
        Properly handles:
        - Values with hash prefixes (#120,568)
        - Values with commas (120,568)
        - Values with SR/CR prefixes (SR-120568)
        - Plain numeric values (120568)
        - Empty or None values (returns "UNKNOWN")
        
        Args:
            value: The SysAid ticket value to standardize
            
        Returns:
            str: Standardized ticket number
        """
        if not value or pd.isna(value) or str(value).strip() == '':
            return "UNKNOWN"
        
        value = str(value).strip()
        
        # Remove hash prefix
        value = re.sub(r'^#', '', value)
        
        # Remove SR- or CR- prefixes
        value = re.sub(r'^(SR|CR)-', '', value)
        
        # Remove commas
        value = value.replace(',', '')
        
        return value
    
    def get_column_match(self, df, column_options):
        """
        Find a column in a DataFrame based on potential column names.
        
        Args:
            df: DataFrame to search
            column_options: List of possible column names
            
        Returns:
            str: Found column name, or None if not found
        """
        # First check for exact matches (case-insensitive)
        for option in column_options:
            matches = [col for col in df.columns if option.upper() == col.upper()]
            if matches:
                return matches[0]
        
        # Then check for partial matches (case-insensitive)
        for option in column_options:
            matches = [col for col in df.columns if option.upper() in col.upper()]
            if matches:
                return matches[0]
        
        return None


class SysAidFileStrategy(SysAidDataStrategy):
    """
    Strategy for loading SysAid data from an Excel file.
    """
    
    def load_data(self):
        """
        Load SysAid ticket information from an Excel file.
        
        Returns:
            DataFrame with SysAid data, or None if loading fails
        """
        try:
            # Get the file path from configuration
            file_path = self.config.get("file_path") or self.paths.get("sysaid_input")
            
            # Check if the file exists
            if not os.path.exists(file_path):
                log_message(f"SysAid file not found: {file_path}", "WARNING")
                return None
                
            log_message(f"Loading SysAid ticket information from: {file_path}")
            
            # Try to load the Excel file with the specific sheet name "Report"
            try:
                sysaid_df = pd.read_excel(file_path, sheet_name="Report")
                log_message("Reading SysAid data from 'Report' sheet")
            except Exception as e:
                # If "Report" sheet doesn't exist, try loading the default sheet
                log_message(f"Could not read 'Report' sheet: {str(e)}", "WARNING")
                sysaid_df = pd.read_excel(file_path)
                log_message("Reading SysAid data from default sheet")
            
            # Find the ticket column from our list of options
            ticket_col = self.get_column_match(sysaid_df, SYSAID_TICKET_COL_OPTIONS)
            
            # If no ticket column found, can't proceed
            if not ticket_col:
                log_message(f"No ticket column found. Looked for: {', '.join(SYSAID_TICKET_COL_OPTIONS)}", "WARNING")
                return None
            
            # Ensure SysAid ticket column is a string
            sysaid_df[ticket_col] = sysaid_df[ticket_col].astype(str)
            
            # Add standardized column
            sysaid_df['Standardized_SysAid'] = sysaid_df[ticket_col].apply(self.standardize_sysaid)
            
            # Record count for completeness tracking
            record_count = len(sysaid_df)
            log_message(f"Loaded SysAid data with {record_count} tickets")
            
            # Count unique standardized tickets
            unique_std_tickets = sysaid_df['Standardized_SysAid'].nunique()
            log_message(f"Found {unique_std_tickets} unique standardized SysAid tickets")
            
            # Update record counter
            record_counter.update_source_counts(
                source_type="sysaid",
                file_name=file_path,
                original_count=record_count,
                final_count=record_count
            )
            
            return sysaid_df
            
        except Exception as e:
            log_error(e, "Error loading SysAid data from file")
            return None


class SysAidApiStrategy(SysAidDataStrategy):
    """
    Strategy for loading SysAid data from an API.
    """
    
    def __init__(self, config=None):
        """
        Initialize the API strategy with configuration.
        
        Args:
            config: Dictionary with configuration overrides
        """
        super().__init__(config)
        self.api_url = self.config.get("api_url", "")
        self.api_key = self.config.get("api_key", "")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.cache_file = os.path.join(self.paths.get("cache_dir", "cache"), "sysaid_api_cache.json")
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_delay = self.config.get("retry_delay", 2)
        self.cache_ttl = self.config.get("cache_ttl", 86400)  # 24 hours in seconds
    
    def load_data(self):
        """
        Load SysAid ticket information from the API.
        
        Returns:
            DataFrame with SysAid data, or None if loading fails
        """
        # First check if we have a valid cached result
        cached_data = self._load_from_cache()
        if cached_data is not None:
            return cached_data
        
        try:
            # Make API request with retries
            data = self._request_with_retry()
            
            if not data:
                log_message("No data received from SysAid API", "WARNING")
                return None
            
            # Convert to DataFrame
            sysaid_df = pd.DataFrame(data)
            
            # Find the ticket column from our list of options
            ticket_col = self.get_column_match(sysaid_df, SYSAID_TICKET_COL_OPTIONS)
            
            # If no ticket column found, can't proceed
            if not ticket_col:
                log_message(f"No ticket column found in API response. Looked for: {', '.join(SYSAID_TICKET_COL_OPTIONS)}", "WARNING")
                return None
            
            # Ensure SysAid ticket column is a string
            sysaid_df[ticket_col] = sysaid_df[ticket_col].astype(str)
            
            # Add standardized column
            sysaid_df['Standardized_SysAid'] = sysaid_df[ticket_col].apply(self.standardize_sysaid)
            
            # Cache the result
            self._save_to_cache(sysaid_df)
            
            # Record count for completeness tracking
            record_count = len(sysaid_df)
            log_message(f"Loaded SysAid data with {record_count} tickets from API")
            
            # Count unique standardized tickets
            unique_std_tickets = sysaid_df['Standardized_SysAid'].nunique()
            log_message(f"Found {unique_std_tickets} unique standardized SysAid tickets")
            
            # Update record counter
            record_counter.update_source_counts(
                source_type="sysaid_api",
                file_name="api_request",
                original_count=record_count,
                final_count=record_count
            )
            
            return sysaid_df
            
        except Exception as e:
            log_error(e, "Error loading SysAid data from API")
            return None
    
    def _request_with_retry(self):
        """
        Make API request with retries on failure.
        
        Returns:
            dict: API response data
        """
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            attempt += 1
            
            try:
                log_message(f"SysAid API request attempt {attempt} of {self.max_retries}...")
                
                # Make the API request
                response = requests.get(
                    self.api_url,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=30
                )
                
                # Check if we got a valid response
                if response.status_code == 200:
                    data = response.json()
                    log_message(f"API request successful: received {len(data)} records")
                    return data
                else:
                    log_message(f"API request failed with status code {response.status_code}: {response.text}", "WARNING")
                    
            except Exception as e:
                last_error = e
                log_message(f"API request error: {str(e)}", "WARNING")
            
            # If we're going to retry, wait a bit
            if attempt < self.max_retries:
                wait_time = self.retry_delay * attempt
                log_message(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        # If we get here, all attempts failed
        log_error(last_error, "All API request attempts failed")
        return None
    
    def _load_from_cache(self):
        """
        Load SysAid data from cache file if valid.
        
        Returns:
            DataFrame: Cached SysAid data, or None if cache is invalid
        """
        try:
            # Check if cache file exists
            if not os.path.exists(self.cache_file):
                return None
            
            # Check cache file age
            file_age = time.time() - os.path.getmtime(self.cache_file)
            if file_age > self.cache_ttl:
                log_message(f"Cache file expired ({file_age:.1f} seconds old)", "INFO")
                return None
            
            # Load cache
            log_message(f"Loading SysAid data from cache: {self.cache_file}")
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Convert cache to DataFrame
            cache_df = pd.DataFrame(cache_data["data"])
            
            # Validate cache
            if len(cache_df) == 0:
                log_message("Cache file contains no data", "WARNING")
                return None
            
            log_message(f"Loaded {len(cache_df)} SysAid records from cache (created {cache_data['timestamp']})")
            return cache_df
            
        except Exception as e:
            log_message(f"Error loading from cache: {str(e)}", "WARNING")
            return None
    
    def _save_to_cache(self, sysaid_df):
        """
        Save SysAid data to cache file.
        
        Args:
            sysaid_df: DataFrame with SysAid data
        """
        try:
            # Create cache directory if needed
            cache_dir = os.path.dirname(self.cache_file)
            os.makedirs(cache_dir, exist_ok=True)
            
            # Prepare cache data
            cache_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "data": sysaid_df.to_dict(orient="records")
            }
            
            # Save to cache file
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
            
            log_message(f"Saved {len(sysaid_df)} SysAid records to cache")
            
        except Exception as e:
            log_message(f"Error saving to cache: {str(e)}", "WARNING")


class SysAidIntegrator:
    """
    Integrates SysAid ticket information with audit data.
    Uses Strategy pattern for different data sources.
    """
    
    def __init__(self, data_source_strategy="file", config=None):
        """
        Initialize with specified data source strategy.
        
        Args:
            data_source_strategy: Strategy for loading SysAid data
                "file" - Load from exported file
                "api" - Load from API
            config: Dictionary with configuration overrides
        """
        self.config = config or SYSAID
        self.paths = PATHS
        self.strategy = self._create_strategy(data_source_strategy)
        self.session_map_cache = os.path.join(self.paths.get("cache_dir", "cache"), "sysaid_session_map.json")
        self._sysaid_data = None
        self._sysaid_lookup = {}
    
    def _create_strategy(self, strategy_type):
        """
        Create appropriate strategy based on type.
        
        Args:
            strategy_type: Type of strategy to create
            
        Returns:
            SysAidDataStrategy: Configured strategy object
        """
        if strategy_type.lower() == "api":
            return SysAidApiStrategy(self.config)
        else:
            return SysAidFileStrategy(self.config)
    
    @handle_exception
    def load_sysaid_data(self):
        """
        Load SysAid ticket data using the configured strategy.
        
        Returns:
            DataFrame with SysAid data
        """
        log_section("Loading SysAid Data")
        
        # Use the strategy to load data
        self._sysaid_data = self.strategy.load_data()
        
        # Build lookup for quick reference
        if self._sysaid_data is not None:
            self._build_sysaid_lookup()
        
        return self._sysaid_data
    
    @handle_exception
    def enhance_session_timeline(self, session_df):
        """
        Enhance session timeline with SysAid information.
        
        Args:
            session_df: Session timeline DataFrame
            
        Returns:
            DataFrame with added SysAid information
        """
        log_section("Enhancing Timeline with SysAid Data")
        
        if session_df is None or len(session_df) == 0:
            log_message("No session data to enhance", "WARNING")
            return session_df
        
        # Create a copy of the session data
        enhanced_df = session_df.copy()
        
        # Load SysAid data if not already loaded
        if self._sysaid_data is None:
            self.load_sysaid_data()
        
        # Get column mappings
        session_col = self._get_column_match(enhanced_df, SESSION_COL_OPTIONS)
        sysaid_col = self._get_column_match(enhanced_df, SAP_SYSAID_COL_OPTIONS)
        
        # Add SysAid ticket column if it doesn't exist
        if 'SYSAID #' not in enhanced_df.columns:
            enhanced_df['SYSAID #'] = ""
            log_message("Added 'SYSAID #' column to session data")
        
        # If no SysAid data is available, return early
        if self._sysaid_data is None:
            log_message("No SysAid data available to enhance session timeline", "WARNING")
            return enhanced_df
        
        # Map sessions to SysAid tickets
        if session_col:
            log_message(f"Mapping SysAid tickets using session column: {session_col}")
            session_to_sysaid = self._map_sessions_to_sysaid(enhanced_df, session_col, sysaid_col)
            
            # Apply the session mapping
            enhanced_df = self._apply_sysaid_mapping(enhanced_df, session_col, session_to_sysaid)
        elif sysaid_col:
            # Direct mapping using SysAid column
            log_message(f"Enhancing timeline using direct SysAid column: {sysaid_col}")
            enhanced_df = self._apply_direct_sysaid_mapping(enhanced_df, sysaid_col)
        else:
            log_message("No session or SysAid column found, cannot enhance timeline", "WARNING")
        
        return enhanced_df
    
    def _build_sysaid_lookup(self):
        """
        Build a lookup dictionary for quick SysAid ticket matching.
        """
        if self._sysaid_data is None:
            return
        
        self._sysaid_lookup = {}
        log_message("Building SysAid lookup dictionary...")
        
        # Find ticket column
        ticket_col = self._get_column_match(self._sysaid_data, SYSAID_TICKET_COL_OPTIONS)
        if not ticket_col:
            log_message("No ticket column found in SysAid data", "ERROR")
            return
        
        for _, row in self._sysaid_data.iterrows():
            # Get original and standardized ticket
            original_ticket = str(row[ticket_col]).strip()
            standardized_ticket = row['Standardized_SysAid']
            
            # Skip UNKNOWN tickets
            if standardized_ticket == "UNKNOWN":
                continue
            
            # Store the ticket data
            ticket_data = {
                "original_ticket": original_ticket,
                "standardized_ticket": standardized_ticket
            }
            
            # Add all available columns from the row
            for col in self._sysaid_data.columns:
                if col != ticket_col and col != 'Standardized_SysAid':
                    ticket_data[col] = row.get(col, "")
            
            # Store using multiple keys for better matching
            self._sysaid_lookup[standardized_ticket] = ticket_data
            self._sysaid_lookup[original_ticket] = ticket_data
            
            # Store with # prefix if it doesn't already have one
            if not original_ticket.startswith('#'):
                self._sysaid_lookup[f"#{original_ticket}"] = ticket_data
            
            # Store without # prefix if it has one
            if original_ticket.startswith('#'):
                self._sysaid_lookup[original_ticket[1:]] = ticket_data
        
        log_message(f"Built SysAid lookup with {len(self._sysaid_lookup)} entries")
    
    def _get_column_match(self, df, column_options):
        """
        Find a column in a DataFrame based on potential column names.
        
        Args:
            df: DataFrame to search
            column_options: List of possible column names
            
        Returns:
            str: Found column name, or None if not found
        """
        # Check for exact matches first
        for option in column_options:
            if option in df.columns:
                return option
        
        # Then check for case-insensitive matches
        df_cols_lower = [col.lower() for col in df.columns]
        for option in column_options:
            option_lower = option.lower()
            if option_lower in df_cols_lower:
                idx = df_cols_lower.index(option_lower)
                return df.columns[idx]
        
        return None
    
    def _map_sessions_to_sysaid(self, df, session_col, sysaid_col=None):
        """
        Map session IDs to SysAid values.
        
        Args:
            df: Session data DataFrame
            session_col: Name of session column
            sysaid_col: Name of SysAid column (optional)
            
        Returns:
            Dict mapping session IDs to SysAid values
        """
        session_to_sysaid = {}
        
        # Try to load existing mapping first
        cached_map = self._load_session_map_cache()
        if cached_map:
            session_to_sysaid = cached_map
        
        # Get unique session IDs
        session_ids = df[session_col].unique()
        log_message(f"Mapping {len(session_ids)} unique sessions to SysAid values")
        
        # Keep track of new or updated mappings
        updated_mappings = False
        
        for session_id in session_ids:
            # Skip if already in cached map
            if str(session_id) in session_to_sysaid and session_to_sysaid[str(session_id)] != "UNKNOWN":
                continue
            
            subset = df[df[session_col] == session_id]
            
            # If we have a SysAid column, use it for mapping
            if sysaid_col and sysaid_col in df.columns:
                sysaid_values = subset[sysaid_col].dropna().unique()
                
                # Skip if no SysAid values
                if len(sysaid_values) == 0:
                    session_to_sysaid[str(session_id)] = "UNKNOWN"
                    continue
                
                # Standardize all SysAid values in this session
                std_values = [self.strategy.standardize_sysaid(val) for val in sysaid_values]
                unique_std_values = list(set(std_values))
                
                # Remove UNKNOWN from the unique values
                non_unknown = [val for val in unique_std_values if val != "UNKNOWN"]
                
                # If we have non-UNKNOWN values, use those
                if non_unknown:
                    # If only one, use it
                    if len(non_unknown) == 1:
                        session_to_sysaid[str(session_id)] = non_unknown[0]
                    else:
                        # Multiple non-UNKNOWN, take the most frequent
                        value_counts = {}
                        for val in std_values:
                            if val != "UNKNOWN":
                                value_counts[val] = value_counts.get(val, 0) + 1
                        
                        most_common = max(value_counts.items(), key=lambda x: x[1])[0]
                        session_to_sysaid[str(session_id)] = most_common
                else:
                    session_to_sysaid[str(session_id)] = "UNKNOWN"
            else:
                # No SysAid column to map from
                session_to_sysaid[str(session_id)] = "UNKNOWN"
            
            updated_mappings = True
        
        # Log the mapping results
        log_message("Session to SysAid mapping results:")
        unknown_count = sum(1 for v in session_to_sysaid.values() if v == "UNKNOWN")
        known_count = len(session_to_sysaid) - unknown_count
        log_message(f"  Total sessions: {len(session_to_sysaid)}")
        log_message(f"  Sessions with known SysAid: {known_count}")
        log_message(f"  Sessions with unknown SysAid: {unknown_count}")
        
        # Save updated mapping
        if updated_mappings:
            self._save_session_map_cache(session_to_sysaid)
        
        return session_to_sysaid
    
    def _apply_sysaid_mapping(self, df, session_col, session_to_sysaid):
        """
        Apply SysAid mapping to session data.
        
        Args:
            df: Session data DataFrame
            session_col: Name of session column
            session_to_sysaid: Dict mapping session IDs to SysAid values
            
        Returns:
            DataFrame with SysAid information added
        """
        # Add mapped SysAid column
        df['Mapped_SysAid'] = df[session_col].astype(str).map(session_to_sysaid)
        
        # Initialize columns
        sysaid_fields = [
            'SYSAID #',
            'Title',
            'SysAid Description',
            'Notes',
            'Request user',
            'Process manager',
            'Request time'
        ]
        
        for field in sysaid_fields:
            if field not in df.columns:
                df[field] = ""
        
        # Count updates
        ticket_count = 0
        
        # Apply SysAid data based on mapped values
        for mapped_ticket, ticket_data in self._sysaid_lookup.items():
            # Get rows with this SysAid value
            mask = df['Mapped_SysAid'] == mapped_ticket
            count = mask.sum()
            
            if count > 0:
                # Update the main SysAid reference column
                df.loc[mask, 'SYSAID #'] = mapped_ticket
                
                # Update all available fields
                for field, value in ticket_data.items():
                    if field in df.columns:
                        df.loc[mask, field] = value
                    elif field == 'Description':  # Special case for Description field
                        df.loc[mask, 'SysAid Description'] = value
                
                ticket_count += count
        
        log_message(f"Added SysAid information to {ticket_count} rows")
        
        return df
    
    def _apply_direct_sysaid_mapping(self, df, sysaid_col):
        """
        Apply SysAid mapping directly using SysAid column.
        
        Args:
            df: Session data DataFrame
            sysaid_col: Name of SysAid column
            
        Returns:
            DataFrame with SysAid information added
        """
        # Initialize columns
        sysaid_fields = [
            'SYSAID #',
            'Title',
            'SysAid Description',
            'Notes',
            'Request user',
            'Process manager',
            'Request time'
        ]
        
        for field in sysaid_fields:
            if field not in df.columns:
                df[field] = ""
        
        # Count updates
        ticket_count = 0
        
        # Add standardized SysAid column
        df['Standardized_SysAid'] = df[sysaid_col].apply(self.strategy.standardize_sysaid)
        
        # Apply SysAid data based on standardized values
        for idx, row in df.iterrows():
            std_ticket = row['Standardized_SysAid']
            
            if std_ticket != "UNKNOWN" and std_ticket in self._sysaid_lookup:
                ticket_data = self._sysaid_lookup[std_ticket]
                
                # Update the main SysAid reference column
                df.at[idx, 'SYSAID #'] = std_ticket
                
                # Update all available fields
                for field, value in ticket_data.items():
                    if field in df.columns:
                        df.at[idx, field] = value
                    elif field == 'Description':  # Special case for Description field
                        df.at[idx, 'SysAid Description'] = value
                
                ticket_count += 1
        
        log_message(f"Added SysAid information to {ticket_count} rows using direct mapping")
        
        return df
    
    def _load_session_map_cache(self):
        """
        Load the cached session-to-SysAid mapping.
        
        Returns:
            Dict: Cached mapping, or empty dict if not available
        """
        try:
            if os.path.exists(self.session_map_cache):
                log_message(f"Loading cached session-to-SysAid mapping")
                with open(self.session_map_cache, 'r') as f:
                    session_map = json.load(f)
                
                log_message(f"Loaded mapping with {len(session_map)} sessions")
                return session_map
        except Exception as e:
            log_message(f"Error loading cached session map: {str(e)}", "WARNING")
        
        return {}
    
    def _save_session_map_cache(self, session_map):
        """
        Save the session-to-SysAid mapping for future use.
        
        Args:
            session_map: Dict mapping session IDs to SysAid values
        """
        try:
            # Create cache directory if needed
            cache_dir = os.path.dirname(self.session_map_cache)
            os.makedirs(cache_dir, exist_ok=True)
            
            log_message(f"Saving session-to-SysAid mapping with {len(session_map)} entries")
            with open(self.session_map_cache, 'w') as f:
                json.dump(session_map, f, indent=2)
            log_message(f"Session mapping saved to cache: {self.session_map_cache}")
        except Exception as e:
            log_message(f"Error saving session map: {str(e)}", "WARNING")
