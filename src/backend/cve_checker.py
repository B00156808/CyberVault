import os
import json
import requests
from datetime import datetime

last_update_file = 'last_update.txt'

def get_last_update():
    """Fetch the last update timestamp or commit SHA from the last_update.txt file."""
    if os.path.exists(last_update_file):
        with open(last_update_file, 'r') as file:
            return file.read().strip()
    return None

def update_last_update(timestamp):
    """Update the last update timestamp or commit SHA in the last_update.txt file."""
    with open(last_update_file, 'w') as file:
        file.write(timestamp)

def aggregate_cve_data(years_to_download, target_subdir=None):
    """Aggregates all CVE data from specified years and subdirectories into a single JSON file."""
    aggregated_cves = []  # This will hold all the CVE data
    aggregated_file = "aggregated_cve_database.json"

    last_update = get_last_update()  # This will store the last commit SHA or timestamp
    
    for year in years_to_download:
        # Construct the base URL for the year directory
        year_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}"
        
        # Request the file listing (directories corresponding to months, weeks, etc.)
        response = requests.get(f"https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/{year}")
        if response.status_code != 200:
            print(f"Error fetching files for {year}: {response.status_code}")
            continue
        
        directories = response.json()
        for directory in directories:
            # Only consider directories (not files)
            if directory["type"] == "dir":
                # If a specific subdirectory is specified, check if it matches
                if target_subdir and directory["name"] != target_subdir:
                    continue  # Skip this subdirectory if it doesn't match
                
                # Fetch all the JSON files from this directory
                subdirectory_url = directory["url"]
                subdirectory_response = requests.get(subdirectory_url)
                if subdirectory_response.status_code != 200:
                    print(f"Error fetching subdirectory {directory['name']} for year {year}")
                    continue

                files_in_subdir = subdirectory_response.json()
                for file in files_in_subdir:
                    if file["name"].endswith(".json"):
                        # Extract the commit SHA from the `git_url` field
                        file_commit_sha = file['git_url'].split('/')[-1]  # This is the commit SHA
                        
                        # Compare the commit SHA to the last update (previous SHA)
                        if last_update is None or file_commit_sha != last_update:
                            # Now download the actual CVE file content
                            cve_json_url = file["download_url"]
                            print(f"Downloading CVE data from {cve_json_url}")
                            cve_response = requests.get(cve_json_url)
                            if cve_response.status_code == 200:
                                try:
                                    cve_data = cve_response.json()
                                    # Each JSON file contains a single CVE, so we directly append it
                                    aggregated_cves.append(cve_data)
                                except json.JSONDecodeError:
                                    print(f"Failed to parse CVE data from {cve_json_url}")
                            else:
                                print(f"Error downloading CVE file {file['name']} from {cve_json_url}")

    if aggregated_cves:
        # Save the aggregated CVEs to a single JSON file
        with open(aggregated_file, "w", encoding="utf-8") as outfile:
            json.dump(aggregated_cves, outfile, indent=4)
        print(f"Successfully aggregated {len(aggregated_cves)} CVEs into {aggregated_file}")
        # Update the last update timestamp to the current commit SHA
        update_last_update(file_commit_sha)
    else:
        print("No new CVE files found since last update.")
    
    return aggregated_file

# Example usage:
# This would aggregate CVEs for the years 2023 and 2024, but only for the `1xxx` subdirectory.
aggregated_file = aggregate_cve_data(["2023"], target_subdir="1xxx")
