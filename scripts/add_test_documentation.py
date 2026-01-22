#!/usr/bin/env python3
"""
Add Documentation sections to all test function docstrings.

This script scans all test files and adds a Documentation: section to test
function docstrings that don't already have one.
"""

import re
import sys
import os
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))
from test_documentation_mapping import get_documentation_url


def has_documentation_in_docstring(docstring: str) -> bool:
    """Check if a docstring already has a Documentation: section."""
    return 'Documentation:' in docstring if docstring else False


def add_documentation_to_docstring(docstring: str, doc_url: str) -> str:
    """
    Add Documentation: section to a docstring if not present.

    Args:
        docstring: Original docstring
        doc_url: Documentation URL to add

    Returns:
        Updated docstring with Documentation section
    """
    if not docstring:
        # Create a new docstring
        return f'"""\n    Documentation: {doc_url}\n    """'

    # Docstring exists - add Documentation before closing quotes
    # Remove leading/trailing quotes and whitespace
    lines = docstring.strip().split('\n')

    # Find where to insert Documentation (before closing quotes or Severity if present)
    insert_index = len(lines)

    # Check if there's a Severity line
    for i, line in enumerate(lines):
        if line.strip().startswith('Severity:'):
            insert_index = i
            break

    # Add Documentation line
    doc_line = f'    Documentation: {doc_url}'

    # Insert the documentation
    lines.insert(insert_index, '')
    lines.insert(insert_index + 1, doc_line)

    return '\n'.join(lines)


def process_test_file(file_path: Path) -> int:
    """
    Process a single test file and add documentation to test functions.

    Args:
        file_path: Path to test file

    Returns:
        Number of tests updated
    """
    print(f"Processing {file_path.name}...")

    with open(file_path, 'r') as f:
        content = f.read()

    # Pattern to match test function with docstring
    # Group 1: function definition
    # Group 2: full docstring with quotes
    pattern = r'(def (test_\w+)\([^)]*\):)\s*("""[^"]*(?:"""|$)|\'\'\'[^\']*(?:\'\'\'|$))?'

    updates_made = 0
    modified_content = content

    # Find all test functions
    for match in re.finditer(pattern, content):
        func_def = match.group(1)
        func_name = match.group(2)
        docstring = match.group(3) if match.group(3) else None

        # Check if documentation already exists
        if docstring and has_documentation_in_docstring(docstring):
            continue

        # Get documentation URL
        doc_url = get_documentation_url(file_path.name, func_name)

        # Add or update documentation
        if docstring:
            # Update existing docstring
            new_docstring = add_documentation_to_docstring(docstring, doc_url)
            modified_content = modified_content.replace(
                f"{func_def}\n    {docstring}",
                f"{func_def}\n    {new_docstring}"
            )
        else:
            # Add new docstring
            new_docstring = f'"""\n    Documentation: {doc_url}\n    """'
            modified_content = modified_content.replace(
                f"{func_def}",
                f"{func_def}\n    {new_docstring}"
            )

        updates_made += 1
        print(f"  ✓ Added documentation to {func_name}")

    # Write back if changes were made
    if updates_made > 0:
        with open(file_path, 'w') as f:
            f.write(modified_content)

    return updates_made


def main():
    """Main entry point."""
    # Get all test files
    tests_dir = Path(__file__).parent.parent / 'tests'
    test_files = sorted(tests_dir.glob('test_*.py'))

    total_updates = 0

    print("="*80)
    print("Adding Documentation to Test Function Docstrings")
    print("="*80)
    print()

    for test_file in test_files:
        updates = process_test_file(test_file)
        total_updates += updates

        if updates > 0:
            print(f"  Updated {updates} test(s) in {test_file.name}")
        print()

    print("="*80)
    print(f"✓ Complete! Added documentation to {total_updates} test functions.")
    print("="*80)


if __name__ == '__main__':
    main()
