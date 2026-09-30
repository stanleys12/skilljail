import sys, csv
rows = list(csv.reader(open(sys.argv[1])))
print(f"rows: {len(rows)-1}, cols: {len(rows[0]) if rows else 0}")
