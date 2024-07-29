import requests
import sys
import argparse
from bs4 import BeautifulSoup
import re


def get_package_download_url(package_name, version=None):
    if version:
        url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    else:
        url = f"https://pypi.org/pypi/{package_name}/json"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if version:
            download_url = None
            for url_info in data['urls']:
                if url_info['packagetype'] == 'sdist' and url_info['url'].endswith('.tar.gz'):
                    download_url = url_info['url']
                    break
            if not download_url:
                raise Exception(f"No tar.gz download URL found for package {package_name} with version {version}")
            latest_version = version
        else:
            latest_version = data['info']['version']
            download_url = None
            for url_info in data['urls']:
                if url_info['packagetype'] == 'sdist' and url_info['url'].endswith('.tar.gz'):
                    download_url = url_info['url']
                    break
            if not download_url:
                raise Exception(f"No tar.gz download URL found for package {package_name} with latest version")
        return download_url, latest_version
    else:
        raise Exception(f"Failed to fetch data for package {package_name} with version {version}")


def check_pypi_vulnerabilities(package_name, version):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data["vulnerabilities"]
        if (len(vulnerabilities) == 0):
            print(f"No vulnerabilities found for {package_name} {version}")
            return None

        return vulnerabilities
    else:
        return None


def get_package_source(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        source_links = data['info'].get('project_urls', None)
        source = None
        if source_links:
            for key, value in source_links.items():
                if 'source' in key.lower():
                    source = value
                    break
        return source
    else:
        raise Exception(f"Failed to fetch data for package {package_name}")


def get_package_dependencies(package_name, version):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        dependencies = data['info'].get('requires_dist', [])
        return dependencies
    else:
        raise Exception(f"Failed to fetch data for package {package_name} with version {version}")


def get_open_source_vulnerabilities(package_name):
    github_repo_path = get_package_source(package_name)
    if github_repo_path is None:
        return None
    repo_path = github_repo_path.replace("https://github.com/", "")

    url = f"https://api.securityscorecards.dev/projects/github.com/{repo_path}"

    response = requests.get(url, headers={"Accept": "application/json"})

    # Check if the request was successful
    if response.status_code == 200:
        scorecard_data = response.json()
        score = scorecard_data.get("score", None)
        print(f"OpenSSF scorecard={scorecard_data['score']}")
        return score
    else:
        print(f"Failed to fetch scorecard data: {response.status_code}")
        return None


def score_package_with_version(package_name, version):
    url = f'https://security.snyk.io/package/pip/{package_name}/{version}'
    response = requests.get(url)
    html_content = response.text

    soup = BeautifulSoup(html_content, 'html.parser')

    severity_levels = {
        'C': 9,
        'H': 7,
        'M': 5,
        'L': 3
    }

    highest_severity = 0
    severity_explanations = []

    vulnerability_elements = soup.find_all('tr', class_='vue--table__row')
    for element in vulnerability_elements:
        severity_span = element.find('span', class_='vue--severity__label')
        explanation_data = element.find('a', class_='vue--anchor')
        if severity_span and explanation_data:
            severity_text = severity_span.get_text(strip=True)
            explanation = explanation_data.get_text(strip=True)
            severity_value = severity_levels.get(severity_text, 0)
            if severity_text == 'M':
                severity_text = 'Medium level Vulnerabitily'
            elif severity_text == 'C':
                severity_text = 'Critical level Vulnerabitily'
            elif severity_text == 'L':
                severity_text = 'Low level Vulnerabitily'
            elif severity_text == 'H':
                severity_text = 'High level Vulnerabitily'
            severity_explanations.append(f"{severity_text}: {explanation}")
            if severity_value > highest_severity:
                highest_severity = severity_value

    if not severity_explanations:
        return None, 10 - highest_severity
    else:
        severity_explanations.append(f"Url for more information: {url}")

    return severity_explanations, 10 - highest_severity


def get_package_names(dependencies):
    package_names = []
    for dep in dependencies:
        match = re.match(r'^([\w\-\.]+)', dep)
        if match:
            package_names.append(match.group(0).strip())
    return package_names


def score_if_no_version(package_name):
    global version
    url = f'https://snyk.io/advisor/python/{package_name}'
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')

        if soup:
            version_data = soup.find('div', class_='name')
            version = version_data.find('span').text.strip() if version_data else 'N/A'

        score_tag = soup.find('div', class_='health')
        score = score_tag.find('span').text.strip() if score_tag else 'N/A'

        score = int(score.split('/')[0])
        return score / 10, version[1:]

    else:
        print(f"Error: Unavailable to fetch data for package {package_name}")
        return None, None


def generate_report(package_name, version, safety_explanations):
    vulnerabilities = check_pypi_vulnerabilities(package_name, version)

    if not vulnerabilities and not safety_explanations:
        return

    report_file = f"{package_name}_{version}_vulnerability_report.txt"
    with open(report_file, "w", encoding="utf-8") as file:
        file.write(f"Vulnerability Report for {package_name}\n")
        file.write("-" * 40 + "\n\n")
        num_vulnerabilities = len(vulnerabilities)
        print(f"Number of vulnerabilities for {package_name} {version}: {num_vulnerabilities}")
        for vuln in vulnerabilities:
            file.write(f"ID: {vuln['id']}\n")
            file.write(f"Aliases: {', '.join(vuln['aliases'])}\n")
            file.write(f"Details: {vuln['details']}\n")
            file.write(f"Fixed In: {', '.join(vuln['fixed_in'])}\n")
            file.write(f"Link: {vuln['link']}\n")
            file.write(f"Source: {vuln['source']}\n")
            file.write("\n")
        file.write("Safety Explanations:\n")
        file.write("-" * 40 + "\n\n")
        for explanation in safety_explanations:
            file.write(f"{explanation}\n")
    print(f"Report generated: {report_file}")


def calculate_dependency_score(dependencies):
    package_names = get_package_names(dependencies)
    scores = []
    for package_name in package_names:
        safety_score_package, version_scanned = score_if_no_version(package_name)
        open_source_score = get_open_source_vulnerabilities(package_name)
        if open_source_score is None:
            scores.append(safety_score_package)
        else:
            average_score = (safety_score_package + open_source_score) / 2
            scores.append(average_score)
    average_dependency_score = sum(scores) / len(scores)
    return average_dependency_score


def get_safety_score(package_name, version, dependencies):
    package_score = 0
    open_source_score = 0
    safety_score_package, version_scanned = score_if_no_version(package_name)
    safety_explanations, safety_score = score_package_with_version(package_name, version)
    open_source_score = get_open_source_vulnerabilities(package_name)
    if (safety_score_package is not None and safety_score_package < 5) or \
            (safety_score is not None and safety_score < 5) or \
            (open_source_score is not None and open_source_score < 5):
        print(f"Score: {round(safety_score, 1)}")
        generate_report(package_name, version, safety_explanations)
        sys.exit(1)
    if safety_score_package is not None and version_scanned is not None:
        if version_scanned == version:
            if open_source_score:
                package_score = (safety_score_package + open_source_score) / 2
            else:
                package_score = safety_score_package
        else:
            package_score = safety_score
    else:
        package_score = safety_score

    if dependencies:
        average_dependency_score = calculate_dependency_score(dependencies)
        return (average_dependency_score + package_score) / 2, safety_explanations

    return package_score, safety_explanations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package_name")

    args = parser.parse_args()

    package_name = args.package_name
    version = None

    match = re.match(r"^(?P<name>[\w\-]+)-(?P<version>[\d\.]+)$", package_name)

    if match:
        package_name = match.group("name")
        version = match.group("version")
        print(f"Package Name: {package_name}")
        print(f"Version: {version}")

    try:
        download_url, latest_version = get_package_download_url(package_name, version)
        print(f"URL: {download_url}")
        dependencies = get_package_dependencies(package_name, latest_version)
        package_score, safety_explanations = get_safety_score(package_name, latest_version, dependencies)
        print(f"Score: {round(package_score, 1)}")
        generate_report(package_name, latest_version, safety_explanations)

    except Exception as e:
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
