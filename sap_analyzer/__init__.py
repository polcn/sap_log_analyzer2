"""
SAP Analyzer Package

This package provides functionality for analyzing SAP audit logs.
It includes tools for risk detection, pattern analysis, and reporting.
"""

from .utils import log_message, load_audit_report, extract_field_value
from .analysis import (
    analyze_risk_distribution,
    analyze_high_risk_items,
    analyze_key_users,
    analyze_debug_activities,
    analyze_session_patterns,
    analyze_algorithm_improvements
)
from .metadata import load_metadata, save_metadata, update_metadata
from .reporting import generate_text_summary, generate_html_report
from .run import run_analysis, run_analysis_from_audit_tool

# Configuration and constants
VERSION = "1.0.0"
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]

# Export all public components
__all__ = [
    'log_message',
    'load_audit_report',
    'extract_field_value',
    'analyze_risk_distribution',
    'analyze_high_risk_items',
    'analyze_key_users',
    'analyze_debug_activities',
    'analyze_session_patterns',
    'analyze_algorithm_improvements',
    'load_metadata',
    'save_metadata',
    'update_metadata',
    'generate_text_summary',
    'generate_html_report',
    'run_analysis',
    'run_analysis_from_audit_tool',
    'VERSION',
    'RISK_LEVELS'
]
