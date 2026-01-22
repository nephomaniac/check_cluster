#!/usr/bin/env python3
"""
Fix documentation placement in test files.

This script fixes incorrectly placed Documentation lines that are outside docstrings.
"""

import re
from pathlib import Path


def fix_test_file(file_path: Path) -> int:
    """Fix documentation placement in a test file."""
    print(f"Fixing {file_path.name}...")

    with open(file_path, 'r') as f:
        content = f.read()

    # Pattern to find incorrectly placed Documentation lines
    # Matches: closing docstring quotes followed by Documentation line
    pattern = r'(""")\s*\n\s*(Documentation: https?://[^\n]+)\n'

    fixes = 0

    def replacer(match):
        nonlocal fixes
        fixes += 1
        closing_quotes = match.group(1)
        doc_line = match.group(2)
        # Move Documentation inside the docstring
        return f'\n    {doc_line}\n    {closing_quotes}\n'

    fixed_content = re.sub(pattern, replacer, content)

    if fixes > 0:
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        print(f"  ✓ Fixed {fixes} documentation placement(s)")

    return fixes


def main():
    """Main entry point."""
    tests_dir = Path(__file__).parent.parent / 'tests'
    test_files = sorted(tests_dir.glob('test_*.py'))

    total_fixes = 0

    print("=" * 80)
    print("Fixing Documentation Placement in Test Files")
    print("=" * 80)
    print()

    for test_file in test_files:
        fixes = fix_test_file(test_file)
        total_fixes += fixes

    print()
    print("=" * 80)
    print(f"✓ Complete! Fixed {total_fixes} documentation placements.")
    print("=" * 80)


if __name__ == '__main__':
    main()
