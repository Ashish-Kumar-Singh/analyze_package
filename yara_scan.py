import os
import yara
import sys

def scan_directory(directory):
    # Initialize counters
    files_with_matches = 0
    total_matches = 0

    # Load YARA rules from the rule file
    rule_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malicious_test.yara")
    rules = yara.compile(rule_file)

    # Scan each file in the directory
    if os.path.isdir(directory):
        files_with_matches, total_matches = scan_files(directory, rules)
    else:
        match_count = scan_file(directory, rules)
        if match_count is not None and match_count > 0:
            files_with_matches = 1
            total_matches = match_count

    print(f"Scanning complete. Files with matches: {files_with_matches}, Total matches: {total_matches}")

def scan_files(directory, rules):
    files_with_matches = 0
    total_matches = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            match_count = scan_file(file_path, rules)
            if match_count > 0:
                files_with_matches += 1
                total_matches += match_count

    return files_with_matches, total_matches

def scan_file(file_path, rules):
    # Severity mapping
    severity_mapping = {
        "DetectPasswordDumping": "High",
        "DetectWMIandPowerShellDataAccess": "High",
        "DetectTaskSchedulerManipulation": "High",
        "DetectCredentialManagerAccess": "High",
        "DetectSystemInfoAndEventLogTampering": "High",
        "DetectNetLocalgroupUsage": "High",
        "DetectNetUserCommandAdvanced": "High",
        "DetectNetViewUsage": "High",
        "DetectSuspiciousAccessToUserDirectories": "Medium",
        "ChromeAppDataAccess": "Medium",
        "NonPyPIURL": "Low",
    }

    with open(file_path, 'rb') as f:
        data = f.read()

    matches = rules.match(data=data)
    match_count = len(matches)

    # Sort matches by severity
    sorted_matches = sorted(matches, key=lambda x: ("High", "Medium", "Low").index(severity_mapping.get(x.rule, "Low")))

    if sorted_matches:
        print(f"String matches found in file: {file_path}")
        for match in sorted_matches:
            severity = severity_mapping.get(match.rule, "Unknown")
            print(f"Rule: {match.rule} (Severity: {severity})")
            print(f"Matched strings: {match.strings}")
            print()

    return match_count


if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python yara_scan.py <target_directory>")
        sys.exit(1)

    # Get the target directory from the script arguments
    target_directory = sys.argv[1]

    # Call the scan_directory function
    scan_directory(target_directory)