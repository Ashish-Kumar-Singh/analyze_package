import requests
import vulners
import sys


def get_release_document(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        release_doc = data["info"]["docs_url"]
        return release_doc
    else:
        return None

def get_number_of_releases(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        releases = data["releases"]
        num_releases = len(releases)
        return num_releases
    else:
        return None

def get_latest_version(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['info']['version']
    else:
        raise Exception(f"Could not fetch package data for {package_name}")

def check_vulnerabilities(package_name, package_version):
    vulners_api = vulners.Vulners(api_key="G8JE8KBZMVINK9GLA0OM1ZE1UEOXURQNBFD4UL5AW16S55LWMLM0KIEB1DSWEA8N")
    search_query = f"{package_name} {package_version}"
    results = vulners_api.find_all(search_query, limit=50)

    if results:
        vulnerabilities = []
        highest_severity = 0
        latest_vulnerability = None

        for result in results:
            severity = result.get('cvss', {}).get('score', 'Unknown')
            title = result.get('title', 'No title')

            if severity != 'Unknown':
                severity = float(severity)
                if severity > highest_severity:
                    highest_severity = severity
                    vulnerabilities = [title]
                    latest_vulnerability = title
                elif severity == highest_severity:
                    vulnerabilities.append(title)

        if vulnerabilities:
            print(f"Vulnerabilities for {package_name} {package_version}:")
            print(f"Highest severity rating: {highest_severity}")
            print(f"Latest vulnerability: {latest_vulnerability}")
        else:
            print(f"No vulnerabilities found for {package_name} {package_version}")
    else:
        print(f"No vulnerabilities found for {package_name} {package_version}")



# Example usage
if len(sys.argv) > 1:
    package_names = sys.argv[1:]
else:
    package_names = ["requestss", "numpy", "matplotlib"]

for package_name in package_names:
    release_doc = get_release_document(package_name)
    num_releases = get_number_of_releases(package_name)
    latest_version = get_latest_version(package_name)
    check_vulnerabilities(package_name, latest_version)

    if release_doc:
        print(f"Release document for {package_name}: {release_doc}")
    else:
        print(f"No release document found for {package_name}")

    if num_releases:
        print(f"Numbers of versions released {package_name}: {num_releases}")
    else:
        print(f"No versions found {package_name}")
