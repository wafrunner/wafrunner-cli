#!/bin/bash
# Verification script to ensure all required commands exist
# Run this after any conflict resolution or major changes

set -e

echo "Verifying all research commands are present..."

python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from wafrunner_cli.commands.research import app

# Get all commands - some have explicit names, others use function names
all_commands = []
for cmd in app.registered_commands:
    if cmd.name:
        all_commands.append(cmd.name)
    elif hasattr(cmd, 'callback') and hasattr(cmd.callback, '__name__'):
        all_commands.append(cmd.callback.__name__)

commands = sorted(set(all_commands))
required = [
    'github',
    'scrape',
    'classify',
    'init-graph',
    'refine-graph',  # Was accidentally removed - critical to verify
    'init-scdef',
    'update-source',
    'links'
]

print(f"\nFound commands: {commands}")
print(f"\nRequired commands: {required}")

missing = set(required) - set(commands)
if missing:
    print(f"\n❌ ERROR: Missing commands: {missing}")
    print("DO NOT COMMIT - Existing functionality has been removed!")
    sys.exit(1)

extra = set(commands) - set(required)
if extra:
    print(f"\n⚠️  WARNING: Unexpected commands found: {extra}")
    print("(This may be okay, but verify they are intentional)")

print("\n✅ All required commands are present")
sys.exit(0)
EOF

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Command verification passed"
else
    echo "❌ Command verification FAILED - DO NOT COMMIT"
    exit 1
fi
