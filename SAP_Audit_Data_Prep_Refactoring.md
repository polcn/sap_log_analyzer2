# SAP Audit Tool - Data Preparation Module Refactoring

## Overview

This document describes the refactoring of the SAP Audit Data Preparation Module (`sap_audit_data_prep.py`), which is the first phase of the SAP Audit Tool refactoring plan. The purpose of this refactoring was to improve the maintainability, reliability, and extensibility of the data preparation process.

## Key Changes

### 1. Architectural Improvements

- **Factory Pattern Implementation:** Created a base `DataSourceProcessor` class with specialized subclasses for each data source (SM20, CDHDR, CDPOS).
- **Modular Design:** Broke down complex functions into smaller, focused methods with single responsibilities.
- **Centralized Configuration:** Replaced hardcoded paths, patterns, and column names with references to the configuration module.
- **Improved Error Handling:** Applied the `handle_exception` decorator to key functions for standardized error handling.

### 2. Added Functionality

- **Comprehensive Input Validation:** Added validation for each data source with clear error reporting.
- **Enhanced Logging:** Integrated standardized logging functions from the utilities module.
- **Better Field Mapping:** Improved handling of SAP's dynamic column behavior across different export formats.
- **Detailed Progress Reporting:** Added more informative messages about the processing status.

### 3. Code Quality Improvements

- **Docstrings:** Added comprehensive docstrings for all classes and methods.
- **Type Hinting:** Added parameter and return type specifications in docstrings.
- **Error Recovery:** Implemented "best effort" approach to continue processing despite minor issues.
- **Robust Input Handling:** Better handling of missing columns and unusual data formats.

## Implementation Details

### Base DataSourceProcessor Class

The base class provides common functionality for all data source processors:

```python
class DataSourceProcessor:
    """Base class for data source processors."""
    
    def __init__(self, source_type):
        """Initialize a data source processor."""
        self.source_type = source_type
        
    def find_input_file(self):
        """Find the most recent file matching the pattern for this source."""
        # Implementation...
        
    def process(self, input_file, output_file):
        """Process the data source - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement process()")
```

This class defines the interface for all processors and implements common methods like file reading, column standardization, and field mapping.

### Specialized Processors

Three specialized processors were implemented for each data source type:

1. **SM20Processor**: Handles security audit log data with features like dynamic field mapping for different SAP export formats and SysAid ticket reference preservation.

2. **CDHDRProcessor**: Processes change document header files with support for different column name variations and robust datetime handling.

3. **CDPOSProcessor**: Manages change document items with standardization of change indicators and table/field information.

### Validation Methods

Each processor implements source-specific validation methods:

```python
def validate_sm20_data(self, df):
    """
    Validate SM20 data before processing.
    
    Args:
        df: DataFrame containing SM20 data
        
    Returns:
        tuple: (is_valid, missing_columns)
    """
    # Implementation...
```

These methods ensure that the required columns are present and that the data quality meets expectations.

### Main Function

The main function was simplified to use the factory pattern:

```python
@handle_exception
def main():
    """Main function to prepare all SAP data files."""
    log_section("Starting SAP Audit Data Preparation")
    
    # Initialize processors
    processors = {
        "sm20": SM20Processor(),
        "cdhdr": CDHDRProcessor(),
        "cdpos": CDPOSProcessor()
    }
    
    # Process each data source
    results = {}
    for source_type, processor in processors.items():
        input_file = processor.find_input_file()
        if input_file:
            output_file = os.path.join(PATHS["input_dir"], f"{source_type.upper()}.csv")
            results[source_type] = processor.process(input_file, output_file)
        else:
            log_message(f"No {source_type.upper()} file found matching pattern", "WARNING")
            results[source_type] = False
```

This approach makes it easier to add new data sources in the future.

## Testing

A comprehensive test suite was created in `test_sap_audit_data_prep.py` to validate the functionality:

1. **Unit Tests**: Tests for individual methods of each processor class.
2. **Integration Tests**: Tests for the interaction between components.
3. **File Handling Tests**: Tests for file pattern matching and processing.

## Benefits

The refactored module provides several key benefits:

1. **Easier Maintenance**: The modular structure and comprehensive documentation make it easier to understand and modify.

2. **Improved Reliability**: Better error handling and validation catch issues early and provide clear messages.

3. **Enhanced Extensibility**: Adding new data sources simply requires creating a new processor class that implements the interface.

4. **Better Testing**: The modular design facilitates more comprehensive and focused testing.

## Next Steps

This refactoring represents the first phase of the overall SAP Audit Tool refactoring plan. The next phases will include:

1. Refactoring the Session Merger module to use a similar pattern.
2. Updating the Risk Assessment module with modular risk rule implementation.
3. Refactoring the main tool to leverage these improvements.

## Usage Example

```python
# Initialize processors
sm20_processor = SM20Processor()
cdhdr_processor = CDHDRProcessor()
cdpos_processor = CDPOSProcessor()

# Process each source
sm20_file = sm20_processor.find_input_file()
if sm20_file:
    sm20_processor.process(sm20_file, os.path.join(PATHS["input_dir"], "SM20.csv"))

cdhdr_file = cdhdr_processor.find_input_file()
if cdhdr_file:
    cdhdr_processor.process(cdhdr_file, os.path.join(PATHS["input_dir"], "CDHDR.csv"))

cdpos_file = cdpos_processor.find_input_file()
if cdpos_file:
    cdpos_processor.process(cdpos_file, os.path.join(PATHS["input_dir"], "CDPOS.csv"))
```

This makes the data preparation process more explicit and easier to understand.
