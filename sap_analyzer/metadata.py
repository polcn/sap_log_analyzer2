"""
Metadata functions for SAP audit log analysis.

This module provides functions for loading, saving, and updating metadata
about SAP audit analysis runs, enabling comparison between runs.
"""

import os
import json
import pandas as pd
from datetime import datetime

from .utils import log_message, DEFAULT_METADATA_PATH

def load_metadata(metadata_path=DEFAULT_METADATA_PATH):
    """
    Load metadata from previous runs.
    Returns an empty dict if no metadata exists.
    """
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        log_message(f"Error loading metadata: {str(e)}", "WARNING")
        return {}

def save_metadata(metadata, metadata_path=DEFAULT_METADATA_PATH):
    """
    Save run metadata for future comparison.
    """
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        log_message(f"Saved run metadata to {metadata_path}")
    except Exception as e:
        log_message(f"Error saving metadata: {str(e)}", "WARNING")

def update_metadata(report_data, metadata_path=DEFAULT_METADATA_PATH):
    """
    Update metadata with current run information.
    """
    # Load existing metadata
    metadata = load_metadata(metadata_path)
    
    # Initialize if needed
    if "runs" not in metadata:
        metadata["runs"] = []
    
    # Create metadata for current run
    timeline_df = report_data.get("timeline", pd.DataFrame())
    
    current_run = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_counts": {},
        "detection_counts": {},
        "total_events": len(timeline_df)
    }
    
    # Add risk counts
    if not timeline_df.empty and 'risk_level' in timeline_df.columns:
        current_run["risk_counts"] = timeline_df['risk_level'].value_counts().to_dict()
    
    # Add detection counts
    if not timeline_df.empty and 'risk_description' in timeline_df.columns:
        # BU4 detection
        current_run["detection_counts"]["BU4"] = timeline_df['risk_description'].str.contains(
            r"BU4|dynamic ABAP", case=False, regex=True, na=False).sum()
        
        # Flag detection
        for flag in ["I!", "D!", "G!"]:
            current_run["detection_counts"][flag] = timeline_df['risk_description'].str.contains(
                flag, regex=False, na=False).sum()
        
        # Message code detection
        message_codes = ["CU_M", "CUL", "BUZ", "CUK", "CUN", "CUO", "CUP", "DU9"]
        for code in message_codes:
            current_run["detection_counts"][code] = timeline_df['risk_description'].str.contains(
                code, regex=False, na=False).sum()
    
    # Add current run to metadata
    metadata["runs"].insert(0, current_run)
    
    # Limit to 10 most recent runs
    metadata["runs"] = metadata["runs"][:10]
    
    # Save updated metadata
    save_metadata(metadata, metadata_path)
    
    return True
