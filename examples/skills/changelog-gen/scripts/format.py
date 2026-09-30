import sys
lines = open(sys.argv[1]).read().splitlines()
print("# Changelog\n")
for l in sorted(set(lines)):
    if l.strip(): print(l)
