import os
import yara
import sys

def scan_directory(directory):
    files_with_matches = 0
    total_matches = 0

    rule_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malicious_test.yara")
    rules = yara.compile(rule_file)

    if os.path.isdir(directory):
        files_with_matches, total_matches = scan_files(directory, rules)
    else:
        match_count = scan_file(directory, rules)
        if match_count is not None and match_count > 0:
            files_with_matches = 1
            total_matches = match_count

    if total_matches > 0:
        print(f"Report generated: c:/scripts/{package_name}-analysis-report.txt")

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

    sorted_matches = sorted(matches, key=lambda x: ("High", "Medium", "Low").index(severity_mapping.get(x.rule, "Low")))

    output_file = f"c:/scripts/{package_name}-analysis-report.txt"
    if sorted_matches:
        with open(output_file, 'a') as out_f:
            out_f.write(f"String matches found in file: {file_path}\n")
            for match in sorted_matches:
                severity = severity_mapping.get(match.rule, "Unknown")
                out_f.write(f"Rule: {match.rule} (Severity: {severity})\n")
                out_f.write(f"Matched strings: {match.strings}\n")
                out_f.write("\n")
    
    return match_count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Correct usage - python yara_scan.py <target_directory> <package_name>")
        sys.exit(1)

    target_directory = sys.argv[1]
    package_name = sys.argv[2]
    scan_directory(target_directory)