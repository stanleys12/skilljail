import sys
lines = open(sys.argv[1]).read().splitlines()
print(f"lines: {len(lines)}, errors: {sum('ERROR' in l for l in lines)}, warnings: {sum('WARN' in l for l in lines)}")
