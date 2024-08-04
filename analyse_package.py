import requests
import sys
import argparse
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

        else:
            download_url = None
            for url_info in data['urls']:
                if url_info['packagetype'] == 'sdist' and url_info['url'].endswith('.tar.gz'):
                    download_url = url_info['url']
                    break
            if not download_url:
                raise Exception(f"No tar.gz download URL found for package {package_name} with latest version")
        return download_url
    else:
        raise Exception(f"Failed to fetch data for package {package_name} with version {version}")


def check_pypi_vulnerabilities(package_name, version=None):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data["vulnerabilities"]
        if (len(vulnerabilities) == 0):
            print(f"No vulnerabilities found for {package_name}")
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


def get_package_names(dependencies):
    package_names = []
    for dep in dependencies:
        match = re.match(r'^([\w\-\.]+)', dep)
        if match:
            package_names.append(match.group(0).strip())
    return package_names

def get_package_dependencies(package_name, version=None):
    if version:
        url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    else:
        url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)

    print(url)

    if response.status_code == 200:
        data = response.json()
        try:
            dependencies = data['info'].get('requires_dist', [])
            return dependencies
        except KeyError:
            print(f"No dependencies found for {package_name}")
            return None
    else:
        raise Exception(f"Failed to fetch data for package {package_name}")


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
        print(f"OpenSSF, package {package_name} scorecard={scorecard_data['score']}")
        return score
    else:
        print(f"Failed to fetch scorecard data: {response.status_code}")
        return None


def generate_report(package_name,version= None, vulnerabilities=None):
    if not vulnerabilities:
        return

    if version:
        report_file = f"{package_name}_{version}_vulnerability_report.txt"
    else:
        report_file = f"{package_name}_vulnerability_report.txt"

    with open(report_file, "w", encoding="utf-8") as file:
        file.write(f"Vulnerability Report for {package_name}\n")
        file.write("-" * 40 + "\n\n")
        num_vulnerabilities = len(vulnerabilities)
        print(f"Number of vulnerabilities for {package_name} : {num_vulnerabilities}")
        for vuln in vulnerabilities:
            file.write(f"ID: {vuln['id']}\n")
            file.write(f"Aliases: {', '.join(vuln['aliases'])}\n")
            file.write(f"Details: {vuln['details']}\n")
            file.write(f"Fixed In: {', '.join(vuln['fixed_in'])}\n")
            file.write(f"Link: {vuln['link']}\n")
            file.write(f"Source: {vuln['source']}\n")
            file.write("\n")
    print(f"Report generated: {report_file}")


def calculate_dependency_score(dependencies):
    package_names = get_package_names(dependencies)
    scores = []
    for package_name in package_names:
        open_source_score = get_open_source_vulnerabilities(package_name)
        if open_source_score is not None:
            scores.append(open_source_score)
    average_dependency_score = sum(scores) / len(scores)
    return average_dependency_score


def get_safety_score(package_name,dependencies):
    package_score = 0
    open_source_score = 0
    open_source_score = get_open_source_vulnerabilities(package_name)
    if open_source_score is not None and open_source_score < 5:
        print(f"Score: {round(open_source_score, 1)}")
        sys.exit(1)

    package_score = open_source_score

    if dependencies:
        average_dependency_score = calculate_dependency_score(dependencies)
        if package_score is not None:
            return (average_dependency_score + package_score) / 2
        else:
            return average_dependency_score

    return package_score


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
        download_url = get_package_download_url(package_name, version)
        print(f"URL: {download_url}")
        dependencies = get_package_dependencies(package_name, version)
        vulnerabilities = check_pypi_vulnerabilities(package_name, version)
        if not vulnerabilities:
            print(f"No vulnerabilities found for {package_name}, proceeding with score calculation")
            package_score = get_safety_score(package_name, dependencies)
            print(f"Score: {round(package_score, 1)}")
        else:
            generate_report(package_name,version, vulnerabilities)

    except Exception as e:
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
