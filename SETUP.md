# SAP Audit Tool Setup Guide

This document provides comprehensive instructions for setting up and configuring the SAP Audit Tool. It covers installation, configuration options, environment management, and best practices for handling nested repositories.

## Table of Contents

1. [Installation](#installation)
2. [Configuration Options](#configuration-options)
3. [Running the Tool](#running-the-tool)
4. [Handling Nested Repositories](#handling-nested-repositories)
5. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Python 3.7 or higher
- Git (for repository management)

### Windows Setup

1. Clone the repository:
   ```
   git clone https://github.com/polcn/sap_log_analyzer2.git
   cd sap_log_analyzer2
   ```

2. Run the setup script:
   ```
   setup.bat
   ```

   This will:
   - Create a Python virtual environment in the `venv` directory
   - Install all required dependencies from `requirements.txt`

3. Activate the virtual environment:
   ```
   call venv\Scripts\activate
   ```

### Manual Setup

If you prefer to set up manually or are using a non-Windows system:

1. Create a virtual environment:
   ```
   python -m venv venv
   ```

2. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration Options

The SAP Audit Tool can be configured using multiple methods, in order of precedence:

1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration files (JSON or YAML)
4. Default values (lowest priority)

### Command-Line Arguments

Run the tool with `--help` to see available options:

```
python run_sap_audit.py --help
```

Key options include:
- `--input-dir DIR`: Directory containing input files
- `--output-dir DIR`: Directory for output files
- `--config-file FILE`: Path to configuration file
- `--env-file FILE`: Path to .env file to load
- `--sysaid`: Enable SysAid integration
- `--debug`: Enable debug mode
- `--export-env`: Export sample .env file
- `--export-config`: Export sample config files

### Environment Variables

Environment variables must be prefixed with `SAP_AUDIT_`. You can:

1. Set them directly in your shell:
   ```
   set SAP_AUDIT_DEBUG=true
   ```

2. Create a `.env` file:
   ```
   # Example .env file
   SAP_AUDIT_INPUT_DIR=custom_input
   SAP_AUDIT_DEBUG=true
   ```

3. Generate a sample environment file:
   ```
   python run_sap_audit.py --export-env
   ```
   This creates `.env.sample` which you can copy to `.env` and edit.

### Configuration Files

The tool supports both JSON and YAML configuration files:

1. Generate sample config files:
   ```
   python run_sap_audit.py --export-config
   ```
   This creates `config.sample.json` and `config.sample.yaml`

2. Use a config file when running:
   ```
   python run_sap_audit.py --config-file my_config.yaml
   ```

3. Structure:
   ```yaml
   paths:
     input_dir: input
     output_dir: output
   settings:
     debug: false
     encoding: utf-8-sig
   config:
     output_format: excel
     enable_sysaid: false
   ```

## Running the Tool

Basic usage:
```
python run_sap_audit.py
```

With configuration:
```
python run_sap_audit.py --input-dir input/march_data --output-dir output/march_report --debug
```

With config file:
```
python run_sap_audit.py --config-file configs/march_config.yaml
```

## Handling Nested Repositories

The project contains a nested `sap_log_analyzer2` repository that needs special handling.

### Best Practice Approach

1. **Use Git Submodules** (recommended):
   
   Convert to a proper Git submodule:
   ```
   # Remove the nested .git directory
   rm -rf sap_log_analyzer2/.git
   
   # Add as a proper submodule
   git rm -r --cached sap_log_analyzer2
   git submodule add https://github.com/polcn/sap_log_analyzer2.git sap_log_analyzer2
   git commit -m "Convert nested repo to proper Git submodule"
   ```

2. **Ignore the Nested Repository** (simpler):
   
   We've already added `sap_log_analyzer2/` to `.gitignore` to prevent Git conflicts. This approach means you manage the nested repository separately.

### Updating the Nested Repository

If using the submodule approach:
```
git submodule update --init --recursive  # Initial setup
git submodule update --remote            # Update to latest
```

If using the separate repository approach:
```
cd sap_log_analyzer2
git pull origin master
cd ..
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**:
   ```
   pip install -r requirements.txt
   ```

2. **Path Issues**:
   - Use absolute paths in configuration files or CLI arguments
   - Verify SCRIPT_DIR in sap_audit_config.py is correctly set

3. **Environment Variable Problems**:
   - Check for typos in variable names
   - Ensure they're prefixed with SAP_AUDIT_
   - Use the --debug flag to see loaded configuration values

4. **Git Conflicts with Nested Repository**:
   - Follow the submodule approach in [Handling Nested Repositories](#handling-nested-repositories)

### Getting Help

If issues persist:

1. Enable debug mode to get more detailed logs:
   ```
   python run_sap_audit.py --debug
   ```

2. Check the technical reference documentation:
   ```
   SAP_Audit_Tool_Technical_Reference.md
   ```

3. Review the Git workflow guide:
   ```
   GIT_WORKFLOW_GUIDE.md
