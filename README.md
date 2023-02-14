# snyk-parser
This small script helps to parse and group Snyk's findings (CSV) 

Dependencies:
```
ast
pandas
argparse
```

Use:
```
python3 sort.py -f snyk.csv -o output.txt
```

## Next Goals
- [ ] Take the date when the finding was discovered and then take the severity of the project mentioned and check it against the table (Vulnerability Time Summary Matrix), just remove the post about delayed patches
