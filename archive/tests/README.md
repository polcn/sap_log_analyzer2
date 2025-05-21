# Archived Test Files

This directory contains test files that have been superseded by newer, more comprehensive tests in the main directory. These files are kept for historical reference but are no longer part of the active test suite.

## Archived Tests

| Test File | Replacement | Reason |
|-----------|-------------|--------|
| `test_data_prep_execution.py` | `test_sap_audit_integration.py` | The integration test now covers data preparation execution in context of the whole pipeline. |
| `test_session_merger_execution.py` | `test_sap_audit_integration.py` | The integration test now covers session merger execution in context of the whole pipeline. |
| `test_sap_audit_results.py` | `test_sap_audit_analyzer.py` and `test_sap_audit_integration.py` | The new analyzer tests validate results more comprehensively. |
| `test_field_descriptions.py` | `test_sap_audit_analyzer.py` | The analyzer test module now handles field descriptions. |

## When to Reference These Tests

These archived tests might be useful in the following scenarios:

1. Understanding historical test coverage
2. Referencing specific test cases when debugging legacy features
3. When implementing similar tests for new functionality

## Archiving Process

As tests become superseded, they should be:

1. Documented in `TEST_DOCUMENTATION.md` in the main directory
2. Moved to this archive directory
3. Added to this README file with an explanation

This process ensures we maintain knowledge of our test history while keeping the main directory focused on current tests.
