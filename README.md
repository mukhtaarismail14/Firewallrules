Firewall-RULE-OPTIMISER - a python project for analysing firewall Rules

The firewall-RULE-OPTIMISER (fwo) is a python-based project used to analyse, evaluate and optimise firewall Rules exported from a CSV file.

The tool can:

validate and Load a set of firewall Rules imported from a CSV file
find duplicate Rules
find conflicting Rules
find shadowed Rules
evaluate each RULE based on a hybrid artificial intelligence (AI)/risk model
order Rules based upon their priority
export a cleaned version of the original CSV file
generate a plain-text analysis report
have both command line and Streamlit web user interface
PROJECT FEATURES

Feature 1. CSV RULE loader
The loader takes in a set of firewall Rules from a CSV file and will check every RULE against a pre-defined list of acceptable columns prior to processing the RULE through the rest of the pipeline.

The acceptable column names are:

Id, action, Source, destination, protocol, port

Acceptable actions are:

Permit, deny

Acceptable protocols are:

Tcp, udp, icmp, any, ip

Any wildcard character values i.e. Blank field, any, * and 0.0.0.0/0 are converted to any.

Feature 2. RULE detector
The detector component evaluates each RULE against three criteria for determining whether or not a RULE represents a firewall policy issue:

Duplicate: two Rules which perform the same function. Conflict: two Rules which have the same scope but different actions. Shadow: a RULE further down in the sequence that will never execute due to being covered by an earlier RULE.

Feature 3. AI risk evaluator
The evaluator utilises an combination of:

anomaly detection from isolation forest from scikit-learn
heuristic explainable scoring
The heuristic evaluation component scores each RULE according to the following factors:

unrestricted Source or destination ip addresses
broad cidr range
unrestricted protocol
any port Number
permitted access to sensitive ports (i.e. SSH, RDP, SMB, mysql etc.)
permit/deny
Each RULE receives an evaluation of:

ai_score: score out of 100
ai_level: low, medium or high
ai_reason: human readable description of why the RULE received its particular score
For very small sets with less than 10 entries in total, the evaluator defaults to using only the heuristic portion as the anomaly detection algorithm does not produce meaningful results for extremely small datasets.

Feature 4. Optimizer
The optimizer process:

Removes exact duplicate entries Keeps the first entry of duplicate entries. Assigns each remaining entry a "priority" value. Orders the remaining entries so that higher risk, deny and more restrictive Rules are processed before lower risk, permit and less restrictive Rules.

Higher priority numbers are closer to the end of the optimized RULE set.

Feature 5. Report generator
All components generate two Output FILES:

Output/report.txt Output/cleaned_firewall_rules.CSV

Report includes:

name of Source file
Number of total Rules before optimization vs. After optimization
total Number of duplicate, conflicting and shadowed entries detected
performance times for each step in the pipeline
summary of overall risk
top n highest risk entries
details of identified duplicate/conflicting/shadowed entries
sample View of first n optimized entries
Project layout
A standard project layout would be something similar to this:

Firewall-RULE-OPTIMISER/ | |--app.py |--src/ | |--aimodel.py | |--analyser.py | |--cli.py | |--detectors.py | |--loaders.py | |--OPTIMISER.py | |--report_generator.py | |--data/ | |--rules.CSV-- | |--rules_normal_500.csv-- | |--rules_normal_1000.csv-- | |--rules_invalid.CSV-- | |--tests/ | |--testproject.py | |--Output/ |--report.txt |--cleaned_firewall_rules.CSV

Please Note that the application.py script assumes all pipeline modules will reside within a directory named 'src/'. To modify this behaviour you could place all project FILES in a single directory or simply rename the src directory to whatever name fits your needs.

INSTALLATION
Create and activate a virtual environment:
Windows:

Python -m venv venv Venv\scripts\activate

Macos/linux:

python3 -m venv venv Source venv/bin/activate

Install required packages using pip.
Pip install numpy scikit-learn pandas plotly Streamlit pytest

CSV input FORMAT
You should provide your input CSV with exactly these headers:

Id,action,Source,destination,protocol,port

Sample data:

Id,action,Source,destination,protocol,port 1,permit,any,10.0.0.5/32,tcp,22 2,deny,192.168.1.0/24,any,tcp,445 3,permit,any,any,any,any

Any invalid action, protocol or port specified in a RULE will cause it to be skipped with a warning message during execution.

How to run this tool
Run full console analyser
From your projects root execute the following:

Python src/analyser.py data/Rules.CSV

If you don't specify a CSV path the analyzer will try to default to using the file located at:

Data/Rules.CSV

Run interactive command line menu
Run the following command from your project's root directory:

Python src/cli.py

Options:

perform full analysis pipeline
print summary of all AI evaluation results for each RULE
display highest risk Rules based upon AI evaluation criteria
quit program
Run the Streamlit dashboard
Run the following command from your projects root directory:

Streamlit run app.py

Using the Streamlit dashboard you can upload a CSV file from anywhere you've stored it locally or select from one of several example CSV FILES i've included.

In addition you can filter the displayed Rules based on risk category and/or action type.

Additional features include:

Risk charts displaying aggregated statistics regarding all evaluated Rules.

RULE viewer showing information about each individual RULE including its id, action type (permit/deny), Source and destination ip addresses or networks, protocol type and port(s).

High-risk RULE viewer listing up to n highest risk Rules.

View entire generated report.

Download entire generated report (as txt), entire cleaned CSV file or just the CSV file containing only filtered Rules.

Run the report generator directly
Run the following command from your projects root directory:

Python src/report_generator.py data/Rules.CSV

This will run the entire pipeline and print the generated report to your local terminal window.

Testing your codebase
To run your test file directly you can simply run:

Python3 tests/test_project.py

Or

If you have pytest installed

You can run:
