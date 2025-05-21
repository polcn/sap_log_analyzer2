# SAP Audit Tool - Session Merger Module Refactoring

## Overview

This document describes the refactoring of the SAP Audit Session Merger Module (renamed from `SAP Log Session Merger.py` to `sap_audit_session_merger.py`), which is the second phase of the SAP Audit Tool refactoring plan. The purpose of this refactoring was to improve the maintainability, reliability, and extensibility of the session merging process.

## Key Changes

### 1. Architectural Improvements

- **Factory Pattern Implementation:** Created a base `DataSourceProcessor` class with specialized subclasses for each data source (SM20, CDHDR, CDPOS).
- **Class-Based Structure:** Implemented a `SessionMerger` class to encapsulate the merging logic and maintain state.
- **Centralized Configuration:** Replaced hardcoded paths, columns names, and settings with references to the configuration module.
- **Improved Error Handling:** Applied the `handle_exception` decorator to key functions for standardized error handling.

### 2. Added Functionality

- **Comprehensive Input Validation:** Added validation for each data source with clear error reporting.
- **Enhanced Logging:** Integrated standardized logging functions from the utilities module.
- **Improved Source Matching:** Better handling of column names across different data sources.
- **Detailed Progress Reporting:** Added more informative messages about the merging status.

### 3. Code Quality Improvements

- **Docstrings:** Added comprehensive docstrings for all classes and methods.
- **Modular Design:** Broke down complex functions into smaller, focused methods with clear responsibilities.
- **Error Recovery:** Implemented "best effort" approach to continue processing despite minor issues.
- **Robust Data Handling:** Better handling of missing columns and unusual data formats.

## Implementation Details

### Base DataSourceProcessor Class

The base class provides common functionality for all data source processors:

```python
class DataSourceProcessor:
    """Base class for data source processors in the session merger."""
    
    def __init__(self, source_type):
        """Initialize a data source processor."""
        self.source_type = source_type.upper()
        self.column_map = COLUMNS.get(source_type.lower(), {})
    
    def load_data(self, file_path):
        """Load data from a CSV file."""
        # Implementation...
        
    def standardize_column_names(self, df):
        """Standardize column names to uppercase."""
        # Implementation...
        
    def add_source_identifier(self, df):
        """Add source identifier column to DataFrame."""
        # Implementation...
        
    def process(self, file_path):
        """Process the data source - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement process()")
```

This class defines the interface for all processors and implements common methods like file loading, column standardization, and source identification.

### Specialized Processors

Three specialized processors were implemented for each data source type:

1. **SM20Processor**: Handles security audit log data, focusing on proper datetime conversion and column validation.

2. **CDHDRProcessor**: Processes change document header files with robust handling of datetime fields and duplicate column detection.

3. **CDPOSProcessor**: Manages change document items with standardization of change indicators and consistent key formatting.

### SessionMerger Class

The main class that orchestrates the entire process:

```python
class SessionMerger:
    """Main class for merging SAP logs into a unified session timeline."""
    
    def __init__(self):
        """Initialize session merger."""
        self.sm20_processor = SM20Processor()
        self.cdhdr_processor = CDHDRProcessor()
        self.cdpos_processor = CDPOSProcessor()
        
        # Column mappings and settings
        self.session_cols = COLUMNS["session"]
        self.exclude_fields = SETTINGS["exclude_fields"]
    
    # Methods for handling SysAid references
    def find_sysaid_column(self, df):
        """Find the best column to use for SysAid ticket numbers."""
        # Implementation...
    
    def standardize_sysaid_references(self, df, sysaid_col):
        """Standardize SysAid ticket references to a consistent format."""
        # Implementation...
    
    # Session ID assignment methods
    def assign_session_ids(self, df, user_col, time_col, session_col='Session ID', sysaid_col=None):
        """Assign session IDs to rows."""
        # Implementation...
    
    # Timeline creation methods
    def create_unified_timeline(self, sm20, cdhdr_cdpos):
        """Create a unified timeline from all sources with proper session assignment."""
        # Implementation...
    
    # Main processing method
    def process(self):
        """Main method to process all data sources and create timeline."""
        # Implementation...
```

This class manages the entire workflow from loading data sources to creating the final Excel output.

## Key Improvements in Detail

### 1. Data Validation and Error Handling

Each data processor now includes specific validation methods:

```python
@handle_exception
def validate_sm20_data(self, df):
    """Validate SM20 data before processing."""
    required_columns = [
        self.column_map["user"], 
        self.column_map["date"], 
        self.column_map["time"]
    ]
    return validate_required_columns(df, required_columns, "SM20")
```

This allows for early detection of issues and more informative error messages.

### 2. CDHDR and CDPOS Merging

The merging logic has been improved to handle common issues:

```python
@handle_exception
def merge_cdhdr_cdpos(self, cdhdr, cdpos):
    """Merge CDHDR with CDPOS data."""
    # Various checks:
    # - Handle empty dataframes
    # - Detect missing columns
    # - Find column name variations
    # - Apply robust merging logic
    # Implementation...
```

This approach makes the code more resilient to variations in input data.

### 3. Session ID Assignment

Session ID assignment now follows a clear preference order:

1. Use SysAid ticket numbers if available
2. Fall back to user+date based sessions if no SysAid data

```python
@handle_exception
def assign_session_ids(self, df, user_col, time_col, session_col='Session ID', sysaid_col=None):
    """Assign session IDs to rows, using SysAid ticket numbers if available."""
    # If sysaid_col is not specified, try to find it
    if sysaid_col is None:
        sysaid_col = self.find_sysaid_column(df)
    
    # Use SysAid if available, otherwise fall back to user+date
    if sysaid_col is not None:
        return self.assign_session_ids_by_sysaid(df, sysaid_col, time_col, session_col)
    else:
        return self.assign_session_ids_by_user_date(df, user_col, time_col, session_col)
```

### 4. Timeline Creation

The timeline creation process was broken down into smaller, focused steps:

1. Prepare SM20 data
2. Prepare CDHDR/CDPOS data 
3. Combine records
4. Assign session IDs
5. Sort timeline

This makes the process easier to understand and maintain.

## Testing

A comprehensive test suite was created in `test_sap_audit_session_merger.py` to validate the refactored functionality:

1. **Unit Tests**: Tests for individual methods of each processor class and the merger class
2. **Integration Tests**: Tests for proper interaction between processors and data sources
3. **End-to-End Test**: Test for the complete session merger workflow

## Benefits

The refactored module provides several benefits:

1. **Easier Maintenance**: The class-based structure and comprehensive documentation make it easier to understand and modify.

2. **Improved Reliability**: Better error handling and validation catch issues early and provide clear messages.

3. **Enhanced Extensibility**: Adding new data sources or session ID assignment methods requires minimal changes.

4. **Consistent Integration**: Standard integration with the configuration and utilities modules ensures consistent behavior.

## Next Steps

This refactoring represents the second phase of the overall SAP Audit Tool refactoring plan. The next phases include:

1. Risk Assessment Module refactoring
2. Main Tool integration updates
3. End-to-end testing of the complete workflow

## Usage Example

```python
# Create a session merger
merger = SessionMerger()

# Process all data sources
result = merger.process()

if result:
    print(f"Session timeline generated successfully: {PATHS['session_timeline']}")
else:
    print("Error generating session timeline")
```

The refactored implementation makes the intended workflow clear and explicit at each step.
