import pandas as pd
import ast
import argparse

description = """
    This tool helps to parse Snyk results from CSV and groups vulnerabilities into the text file.
    You just need to provide two arguments:
    -f/--file: Input file in CSV format
    -o/--output: Output file
"""

parser = argparse.ArgumentParser(description)

parser.add_argument("-f", "--file", help = "Input Filename")
parser.add_argument("-o", "--output", help = "Output filename")

arguments = parser.parse_args()

if(arguments.file and arguments.output):
    df = pd.read_csv(arguments.file)
    groupped_df = df.groupby(['PROBLEM_TITLE', 'CVE', 'CWE', 'ISSUE_SEVERITY'], as_index=False, sort=False).agg({'PROJECT_NAME': ','.join})
    groupped_df.to_csv('output.csv', index=False)

    with open(arguments.output, 'w') as f:
        for index, row in groupped_df.iterrows():
            # Name
            f.write(f"Issue Name: {row['PROBLEM_TITLE']}\n")
            # Severity
            f.write(f"Severity: {row['ISSUE_SEVERITY']}\n")
            # CVE
            cve = ast.literal_eval(row['CVE'])
            f.write(f"CVE: ")
            for i in cve:
                f.write(f"{i} ")
            f.write('\n')
            # CWE
            cwe = ast.literal_eval(row['CWE'])
            f.write(f"CWE: ")
            for i in cwe:
                f.write(f"{i} ")
            f.write('\n')
            # Repository
            if(len(row['PROJECT_NAME'].split(',')) == 1):
                f.write(f"Repository:\n")
            else:
                f.write(f"Repositories:\n")
            for repo in set(row['PROJECT_NAME'].split(',')):
                f.write(f"- {repo.split('/')[1]}\n")
            f.write('\n\n')
else:
    print(description)