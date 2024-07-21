import requests
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

def check_vulnerabilities(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data["vulnerabilities"]
        return vulnerabilities
    else:
        return None

# Example usage
if len(sys.argv) > 1:
    package_names = sys.argv[1:]
else:
    package_names = ["requestss", "numpy", "matplotlib"]

for package_name in package_names:
    release_doc = get_release_document(package_name)
    num_releases = get_number_of_releases(package_name)
    vulnerabilities = check_vulnerabilities(package_name)

    if release_doc:
        print(f"Release document for {package_name}: {release_doc}")
    else:
        print(f"No release document found for {package_name}")

    if num_releases:
        print(f"Numbers of versions released {package_name}: {num_releases}")
    else:
        print(f"No versions found {package_name}")

    if vulnerabilities:
        print(f"Vulnerabilities for {package_name}: {vulnerabilities}")
    else:
        print(f"No vulnerabilities found for {package_name}")