 #!/usr/bin/env python3
"""
Script to analyze malicious packages from Shai-Hulud CSV and find projects
using them in DependencyTrack.
"""

import csv
import os
import sys
import requests
import json
from typing import Dict, List, Tuple
from urllib.parse import urljoin

# DependencyTrack API base URL
DT_BASE_URL = os.getenv("DT_BASE_URL")
DT_API_TOKEN = os.getenv("DT_API_TOKEN")

if not DT_BASE_URL:
    print("Error: DT_BASE_URL environment variable is not set", file=sys.stderr)
    sys.exit(1)

if not DT_API_TOKEN:
    print("Error: DT_API_TOKEN environment variable is not set", file=sys.stderr)
    sys.exit(1)

# Cache control - disabled by default
ENABLE_CACHE = os.getenv("ENABLE_CACHE", "").lower() in ("true", "1", "yes")

# CSV URL
CSV_URL = "https://github.com/wiz-sec-public/wiz-research-iocs/raw/refs/heads/main/reports/shai-hulud-2-packages.csv"

# JSON URL
JSON_URL = "https://raw.githubusercontent.com/triconinfotech/shai-hulud-malicious-packages/refs/heads/main/malicious_npm_packages.json"

# API headers
HEADERS = {
    "X-Api-Key": DT_API_TOKEN,
    "Content-Type": "application/json"
}


def download_csv(url: str) -> List[Dict[str, str]]:
    """Download and parse the CSV file."""
    print(f"Downloading CSV from {url}...")
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    # Parse CSV
    csv_content = response.text
    reader = csv.DictReader(csv_content.splitlines())
    packages = list(reader)
    print(f"Downloaded {len(packages)} packages from CSV")
    return packages


def download_json(url: str) -> Dict:
    """Download and parse the JSON file."""
    print(f"Downloading JSON from {url}...")
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    data = response.json()
    print(f"Downloaded {len(data)} packages from JSON")
    return data


def parse_version(version_str: str) -> Tuple[str, List[str]]:
    """
    Parse version string like "= 0.0.7" or "= 3.24.1 || = 3.24.2"
    Returns: (major_version, [all_versions])
    """
    # Remove "= " prefix and split by "||"
    versions = []
    for v in version_str.split("||"):
        v = v.strip()
        if v.startswith("="):
            v = v[1:].strip()
        versions.append(v)

    # Extract major version from first version
    major_version = None
    if versions:
        first_version = versions[0]
        # Major version is typically the first number before the first dot
        parts = first_version.split(".")
        if parts:
            major_version = parts[0]

    return major_version, versions


def check_and_exit_on_error(response: requests.Response, context: str = ""):
    """Check for 401, 403, or 405 errors and exit if found."""
    if response.status_code in (401, 403, 405):
        print(f"Fatal error {response.status_code} {context}: {response.text}", file=sys.stderr)
        sys.exit(1)


def get_all_projects() -> List[Dict]:
    """Get all projects from DependencyTrack, handling pagination."""
    base_url = urljoin(DT_BASE_URL, "/api/v1/project")
    all_projects = []
    page_size = 100
    page_number = 1

    try:
        # First request to get total count
        params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
        response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
        check_and_exit_on_error(response, "getting projects")
        response.raise_for_status()

        # Get total count from header
        total_count_header = response.headers.get('X-Total-Count')
        if total_count_header:
            try:
                total_count = int(total_count_header)
            except ValueError:
                total_count = None
        else:
            total_count = None

        # Process first page
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"Non-JSON response when getting projects: {response.text[:200]}", file=sys.stderr)
            return []

        # Handle both list and paginated response
        if isinstance(data, list):
            all_projects.extend(data)
        elif isinstance(data, dict) and 'items' in data:
            all_projects.extend(data['items'])

        # If we got total count, calculate pages needed
        if total_count is not None:
            total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
            print(f"Found {total_count} total projects across {total_pages} page(s)")

            # Fetch remaining pages
            for page_number in range(2, total_pages + 1):
                params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
                response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
                check_and_exit_on_error(response, f"getting projects page {page_number}")
                response.raise_for_status()

                try:
                    data = response.json()
                except json.JSONDecodeError:
                    print(f"Non-JSON response when getting projects page {page_number}: {response.text[:200]}", file=sys.stderr)
                    continue

                if isinstance(data, list):
                    all_projects.extend(data)
                elif isinstance(data, dict) and 'items' in data:
                    all_projects.extend(data['items'])
        else:
            # If no total count header, check if we got a full page
            # If we got less than page_size, we're done
            if len(all_projects) < page_size:
                print(f"Found {len(all_projects)} projects (no pagination info)")
            else:
                # Keep fetching until we get less than page_size items
                print(f"Found at least {len(all_projects)} projects (fetching all pages...)")
                while True:
                    page_number += 1
                    params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
                    response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
                    check_and_exit_on_error(response, f"getting projects page {page_number}")
                    response.raise_for_status()

                    try:
                        data = response.json()
                    except json.JSONDecodeError:
                        print(f"Non-JSON response when getting projects page {page_number}: {response.text[:200]}", file=sys.stderr)
                        break

                    page_projects = []
                    if isinstance(data, list):
                        page_projects = data
                    elif isinstance(data, dict) and 'items' in data:
                        page_projects = data['items']

                    if not page_projects:
                        break

                    all_projects.extend(page_projects)

                    # If we got less than page_size, we're on the last page
                    if len(page_projects) < page_size:
                        break

        return all_projects
    except requests.exceptions.RequestException as e:
        print(f"Error getting projects: {e}", file=sys.stderr)
        return []

def load_cache() -> Dict[str, List[Dict]]:
    """Load component cache from cache.json if it exists and caching is enabled."""
    if not ENABLE_CACHE:
        return {}
    # Use /app/output if it exists (Docker volume mount), otherwise current directory
    output_dir = '/app/output' if os.path.exists('/app/output') else '.'
    cache_file = os.path.join(output_dir, 'cache.json')
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache = json.load(f)
                print(f"Loaded cache with {len(cache)} projects")
                return cache
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading cache: {e}. Starting with empty cache.")
            return {}
    return {}


def save_cache(cache: Dict[str, List[Dict]]):
    """Save component cache to cache.json if caching is enabled."""
    if not ENABLE_CACHE:
        return
    # Use /app/output if it exists (Docker volume mount), otherwise current directory
    output_dir = '/app/output' if os.path.exists('/app/output') else '.'
    cache_file = os.path.join(output_dir, 'cache.json')
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"Error saving cache: {e}", file=sys.stderr)


def get_project_components(project_uuid: str, cache: Dict[str, List[Dict]] = None) -> List[Dict]:
    """Get all components for a project, handling pagination and using cache if available and enabled."""
    # Check cache first (only if caching is enabled)
    if ENABLE_CACHE and cache is not None and project_uuid in cache:
        return cache[project_uuid]

    # Fetch from API with pagination
    base_url = urljoin(DT_BASE_URL, f"/api/v1/component/project/{project_uuid}")
    all_components = []
    page_size = 100
    page_number = 1

    try:
        # First request to get total count
        params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
        response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
        check_and_exit_on_error(response, f"getting components for project {project_uuid}")

        if response.status_code == 404:
            components = []
            if ENABLE_CACHE and cache is not None:
                cache[project_uuid] = components
            return components

        response.raise_for_status()

        # Get total count from header
        total_count_header = response.headers.get('X-Total-Count')
        if total_count_header:
            try:
                total_count = int(total_count_header)
            except ValueError:
                total_count = None
        else:
            total_count = None

        # Process first page
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"Non-JSON response when getting components for project {project_uuid}: {response.text[:200]}", file=sys.stderr)
            return []

        # Handle both list and paginated response
        if isinstance(data, list):
            all_components.extend(data)
        elif isinstance(data, dict) and 'items' in data:
            all_components.extend(data['items'])
        elif isinstance(data, dict):
            all_components.append(data)

        # If we got total count, calculate pages needed
        if total_count is not None:
            total_pages = (total_count + page_size - 1) // page_size  # Ceiling division

            # Fetch remaining pages
            for page_number in range(2, total_pages + 1):
                params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
                response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
                check_and_exit_on_error(response, f"getting components for project {project_uuid} page {page_number}")
                response.raise_for_status()

                try:
                    data = response.json()
                except json.JSONDecodeError:
                    print(f"Non-JSON response when getting components for project {project_uuid} page {page_number}: {response.text[:200]}", file=sys.stderr)
                    continue

                if isinstance(data, list):
                    all_components.extend(data)
                elif isinstance(data, dict) and 'items' in data:
                    all_components.extend(data['items'])
        else:
            # If no total count header, check if we got a full page
            # If we got less than page_size, we're done
            if len(all_components) < page_size:
                pass  # Already have all components
            else:
                # Keep fetching until we get less than page_size items
                while True:
                    page_number += 1
                    params = {'pageNumber': str(page_number), 'pageSize': str(page_size)}
                    response = requests.get(base_url, headers=HEADERS, params=params, timeout=30)
                    check_and_exit_on_error(response, f"getting components for project {project_uuid} page {page_number}")
                    response.raise_for_status()

                    try:
                        data = response.json()
                    except json.JSONDecodeError:
                        print(f"Non-JSON response when getting components for project {project_uuid} page {page_number}: {response.text[:200]}", file=sys.stderr)
                        break

                    page_components = []
                    if isinstance(data, list):
                        page_components = data
                    elif isinstance(data, dict) and 'items' in data:
                        page_components = data['items']

                    if not page_components:
                        break

                    all_components.extend(page_components)

                    # If we got less than page_size, we're on the last page
                    if len(page_components) < page_size:
                        break

        # Store in cache (only if caching is enabled)
        if ENABLE_CACHE and cache is not None:
            cache[project_uuid] = all_components

        return all_components
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            components = []
            if ENABLE_CACHE and cache is not None:
                cache[project_uuid] = components
            return components
        print(f"Error getting components for project {project_uuid}: {e}", file=sys.stderr)
        return []


def match_component_against_packages(component_name: str, component_version: str, packages_lookup: Dict[str, Dict]) -> Dict[str, List[str]]:
    """
    Match a component against all packages in the CSV lookup.
    Returns: {
        'any_version': [list of package names that match],
        'exact_version': [list of package names with exact version match],
        'major_version': [list of package names with major version match]
    }
    """
    matches = {
        'any_version': [],
        'exact_version': [],
        'major_version': []
    }

    if component_name not in packages_lookup:
        return matches

    package_info = packages_lookup[component_name]
    malicious_versions = package_info['malicious_versions']
    major_version = package_info['major_version']
    all_versions_malicious = package_info.get('all_versions_malicious', False)

    # Any version match
    matches['any_version'].append(component_name)

    # If all versions are malicious, any version matches for exact and major
    if all_versions_malicious:
        matches['exact_version'].append(component_name)
        if component_version:  # If component has a version, it matches
            matches['major_version'].append(component_name)
    else:
        # Strip 'v' prefix if present for comparison
        comp_version_clean = component_version.lstrip('vV') if component_version else ""

        # Check exact version match
        if comp_version_clean in malicious_versions or component_version in malicious_versions:
            matches['exact_version'].append(component_name)

        # Check major version match
        if major_version and comp_version_clean:
            version_parts = comp_version_clean.split(".")
            if version_parts and version_parts[0] == major_version:
                matches['major_version'].append(component_name)

    return matches


def main():
    """Main execution function."""
    print("Starting package analysis...")

    # Download CSV and JSON, then build lookup structure
    try:
        csv_packages = download_csv(CSV_URL)
    except Exception as e:
        print(f"Error downloading CSV: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        json_packages = download_json(JSON_URL)
    except Exception as e:
        print(f"Error downloading JSON: {e}", file=sys.stderr)
        print("Continuing with CSV data only...")
        json_packages = {}

    # Build a lookup dictionary: package_name -> {version_str, malicious_versions, major_version}
    packages_lookup = {}

    # Process CSV packages
    csv_count = 0
    for package_row in csv_packages:
        package_name = package_row.get('Package', '').strip()
        version_str = package_row.get('Version', '').strip()

        if not package_name:
            continue

        major_version, malicious_versions = parse_version(version_str)
        packages_lookup[package_name] = {
            'version_str': version_str,
            'malicious_versions': malicious_versions,
            'major_version': major_version,
            'all_versions_malicious': False,  # CSV always has specific versions
            'source': 'CSV'
        }
        csv_count += 1

    # Process JSON packages
    json_count = 0
    for package_name, package_data in json_packages.items():
        if not package_name:
            continue

        versions = package_data.get('versions', [])

        # If package already exists from CSV, merge versions
        if package_name in packages_lookup:
            existing_versions = set(packages_lookup[package_name]['malicious_versions'])
            new_versions = set(versions)
            all_versions = sorted(list(existing_versions | new_versions))

            # If JSON has empty versions array, all versions are malicious
            all_versions_malicious = len(versions) == 0

            # Rebuild version_str and major_version
            if all_versions_malicious:
                version_str = packages_lookup[package_name]['version_str'] + " || ALL VERSIONS"
            else:
                version_str = ' || '.join([f"= {v}" for v in all_versions])

            major_version = None
            if all_versions:
                first_version = all_versions[0]
                parts = first_version.split(".")
                if parts:
                    major_version = parts[0]

            packages_lookup[package_name] = {
                'version_str': version_str,
                'malicious_versions': all_versions,
                'major_version': major_version,
                'all_versions_malicious': all_versions_malicious,
                'source': 'CSV+JSON'
            }
        else:
            # New package from JSON
            # If versions array is empty, all versions are malicious
            all_versions_malicious = len(versions) == 0
            version_str = ' || '.join([f"= {v}" for v in versions]) if versions else "ALL VERSIONS"
            major_version = None
            if versions:
                first_version = versions[0]
                parts = first_version.split(".")
                if parts:
                    major_version = parts[0]

            packages_lookup[package_name] = {
                'version_str': version_str,
                'malicious_versions': versions,
                'major_version': major_version,
                'all_versions_malicious': all_versions_malicious,
                'source': 'JSON'
            }
            json_count += 1

    print(f"\nLoaded {csv_count} packages from CSV, {json_count} new packages from JSON")
    print(f"Total unique packages: {len(packages_lookup)}\n")

    # Statistics - track per package (store UUID -> {name, version})
    package_stats = {pkg: {
        'projects_any_version': {},  # uuid -> {'name': ..., 'version': ...}
        'projects_exact_version': {},  # uuid -> {'name': ..., 'version': ...}
        'projects_major_version': {}  # uuid -> {'name': ..., 'version': ...}
    } for pkg in packages_lookup.keys()}

    # Load cache
    cache = load_cache()

    # Get all projects
    print("Fetching all projects from DependencyTrack...")
    all_projects = get_all_projects()

    # Limit to first 10 projects for testing
    TEST_MODE = False
    if TEST_MODE:
        all_projects = all_projects[:10]
        print(f"TEST MODE: Processing only first 10 projects (out of {len(get_all_projects())} total)\n")
    else:
        print(f"Found {len(all_projects)} projects to analyze\n")


    # Process each project: get components once, match against all packages
    for idx, project in enumerate(all_projects, 1):
        project_uuid = project.get('uuid')
        project_name = project.get('name', 'Unknown')

        if not project_uuid:
            continue

        # Progress indicator
        if idx % 5 == 0 or idx == 1:
            cached = " (cached)" if ENABLE_CACHE and project_uuid in cache else ""
            print(f"[{idx}/{len(all_projects)}] Processing project: {project_name[:60]}{cached}...", end='\r', flush=True)

        # Get all components for this project (ONCE per project, using cache)
        components = get_project_components(project_uuid, cache)

        # Match each component against all packages in CSV
        for component in components:
            if not component:
                continue

            comp_name = component.get('name', '')
            comp_version = component.get('version', '')

            if not comp_name:
                continue

            # Match this component against all packages
            matches = match_component_against_packages(comp_name, comp_version, packages_lookup)

            # Update statistics for each matching package (store UUID -> {name, version})
            for package_name in matches['any_version']:
                package_stats[package_name]['projects_any_version'][project_uuid] = {
                    'name': project_name,
                    'version': comp_version
                }

            for package_name in matches['exact_version']:
                package_stats[package_name]['projects_exact_version'][project_uuid] = {
                    'name': project_name,
                    'version': comp_version
                }

            for package_name in matches['major_version']:
                package_stats[package_name]['projects_major_version'][project_uuid] = {
                    'name': project_name,
                    'version': comp_version
                }

        # Save results and cache incrementally (every 10 projects)
        if idx % 10 == 0:
            # Build stats structure for saving
            stats = build_stats_from_package_stats(package_stats, packages_lookup)
            save_results(stats, idx, len(all_projects))
            save_cache(cache)
            print(f"  💾 Progress saved ({idx}/{len(all_projects)} projects processed)" + " " * 30)

    print(f"\nCompleted processing {len(all_projects)} projects" + " " * 50)

    # Build final statistics
    stats = build_stats_from_package_stats(package_stats, packages_lookup)

    # Final save
    save_results(stats, len(all_projects), len(all_projects), final=True)
    save_cache(cache)

    # Print summary statistics
    print("\n" + "="*80)
    print("SUMMARY STATISTICS")
    print("="*80)
    print(f"Total packages analyzed: {stats['total_packages']}")
    print(f"Packages with projects found: {stats['packages_with_projects']}")
    print(f"\n1. Projects using packages (any version): {len(stats['total_projects_any_version'])}")
    print(f"2. Projects using exact malicious versions: {len(stats['total_projects_exact_version'])}")
    print(f"3. Projects using same major version: {len(stats['total_projects_major_version'])}")

    # Calculate statistics by source (WIZ vs TRICON)
    wiz_packages = set()
    tricon_packages = set()
    wiz_projects_any = set()
    wiz_projects_exact = set()
    wiz_projects_major = set()
    tricon_projects_any = set()
    tricon_projects_exact = set()
    tricon_projects_major = set()

    for pkg_detail in stats['package_details']:
        source = pkg_detail.get('source', 'Unknown')
        pkg_name = pkg_detail['package']

        # Track packages by source
        if source == 'CSV' or source == 'CSV+JSON':
            wiz_packages.add(pkg_name)
        if source == 'JSON' or source == 'CSV+JSON':
            tricon_packages.add(pkg_name)

        # Track projects by source
        for proj in pkg_detail['projects_any_version']['projects']:
            proj_uuid = proj['uuid']
            if source == 'CSV' or source == 'CSV+JSON':
                wiz_projects_any.add(proj_uuid)
            if source == 'JSON' or source == 'CSV+JSON':
                tricon_projects_any.add(proj_uuid)

        for proj in pkg_detail['projects_exact_version']['projects']:
            proj_uuid = proj['uuid']
            if source == 'CSV' or source == 'CSV+JSON':
                wiz_projects_exact.add(proj_uuid)
            if source == 'JSON' or source == 'CSV+JSON':
                tricon_projects_exact.add(proj_uuid)

        for proj in pkg_detail['projects_major_version']['projects']:
            proj_uuid = proj['uuid']
            if source == 'CSV' or source == 'CSV+JSON':
                wiz_projects_major.add(proj_uuid)
            if source == 'JSON' or source == 'CSV+JSON':
                tricon_projects_major.add(proj_uuid)

    # Print source-specific statistics
    print("\n" + "-"*80)
    print("BY SOURCE")
    print("-"*80)
    print("\nWIZ (CSV):")
    print(f"  Packages found: {len(wiz_packages)}")
    print(f"  Projects using packages (any version): {len(wiz_projects_any)}")
    print(f"  Projects using exact malicious versions: {len(wiz_projects_exact)}")
    print(f"  Projects using same major version: {len(wiz_projects_major)}")
    print("\nTRICON (JSON):")
    print(f"  Packages found: {len(tricon_packages)}")
    print(f"  Projects using packages (any version): {len(tricon_projects_any)}")
    print(f"  Projects using exact malicious versions: {len(tricon_projects_exact)}")
    print(f"  Projects using same major version: {len(tricon_projects_major)}")

    # Print detailed summary table
    if stats['package_details']:
        print("\n" + "="*80)
        print("DETAILED PACKAGE SUMMARY")
        print("="*80)
        print(f"{'Package':<40} {'Source':<12} {'Any Ver':<10} {'Exact Ver':<12} {'Major Ver':<12}")
        print("-" * 100)

        for pkg_detail in sorted(stats['package_details'], key=lambda x: x['projects_any_version']['count'], reverse=True):
            pkg_name = pkg_detail['package']
            any_count = pkg_detail['projects_any_version']['count']
            exact_count = pkg_detail['projects_exact_version']['count']
            major_count = pkg_detail['projects_major_version']['count']

            # Get source indicator
            source = pkg_detail.get('source', 'Unknown')
            if source == 'CSV':
                source_indicator = "[WIZ]"
            elif source == 'JSON':
                source_indicator = "[TRICON]"
            elif source == 'CSV+JSON':
                source_indicator = "[WIZ+TRICON]"
            else:
                source_indicator = "[?]"

            # Get malicious versions
            malicious_versions = pkg_detail['malicious_versions']
            if pkg_detail.get('all_versions_malicious', False):
                malicious_versions_str = "ALL VERSIONS"
            elif malicious_versions:
                malicious_versions_str = ", ".join(malicious_versions[:3])
                if len(malicious_versions) > 3:
                    malicious_versions_str += f" (+{len(malicious_versions)-3} more)"
            else:
                malicious_versions_str = "N/A"

            # Get project names with versions used
            project_info_list = []
            for p in pkg_detail['projects_any_version']['projects']:
                project_info_list.append(f"{p['name']} (v{p['version']})")

            if len(project_info_list) <= 2:
                projects_str = ", ".join(project_info_list)
            else:
                projects_str = ", ".join(project_info_list[:2]) + f" (+{len(project_info_list)-2} more)"

            print(f"{pkg_name[:38]:<40} {source_indicator:<12} {any_count:<10} {exact_count:<12} {major_count:<12}")
            print(f"  Malicious versions: {malicious_versions_str}")
            print(f"  Projects: {projects_str}")
            print()

        print("\n" + "="*80)
        print("PROJECTS AFFECTED")
        print("="*80)

        # Group by project
        projects_affected = {}
        for pkg_detail in stats['package_details']:
            for proj in pkg_detail['projects_any_version']['projects']:
                proj_uuid = proj['uuid']
                proj_name = proj['name']
                if proj_uuid not in projects_affected:
                    projects_affected[proj_uuid] = {
                        'name': proj_name,
                        'packages': []
                    }
                projects_affected[proj_uuid]['packages'].append(pkg_detail['package'])

        for proj_uuid, proj_info in sorted(projects_affected.items(), key=lambda x: len(x[1]['packages']), reverse=True):
            print(f"\n{proj_info['name']} ({len(proj_info['packages'])} malicious package(s)):")
            for pkg_name in proj_info['packages']:
                # Find the package detail to get version info
                pkg_detail = next((p for p in stats['package_details'] if p['package'] == pkg_name), None)
                if pkg_detail:
                    # Get source indicator
                    source = pkg_detail.get('source', 'Unknown')
                    if source == 'CSV':
                        source_indicator = "[WIZ]"
                    elif source == 'JSON':
                        source_indicator = "[TRICON]"
                    elif source == 'CSV+JSON':
                        source_indicator = "[WIZ+TRICON]"
                    else:
                        source_indicator = "[?]"

                    # Find this project's version usage
                    proj_usage = next((p for p in pkg_detail['projects_any_version']['projects'] if p['uuid'] == proj_uuid), None)
                    if proj_usage:
                        version_used = proj_usage.get('version', 'unknown')
                        malicious_versions = pkg_detail['malicious_versions']
                        if pkg_detail.get('all_versions_malicious', False):
                            malicious_str = "ALL VERSIONS"
                        elif malicious_versions:
                            malicious_str = ", ".join(malicious_versions)
                        else:
                            malicious_str = "N/A"

                        # Check for exact match
                        exact_match = any(p['uuid'] == proj_uuid for p in pkg_detail['projects_exact_version']['projects'])
                        # Check for major version match (close match)
                        major_match = any(p['uuid'] == proj_uuid for p in pkg_detail['projects_major_version']['projects'])

                        match_indicator = ""
                        if exact_match:
                            match_indicator = " [EXACT_MATCH]"
                        elif major_match:
                            match_indicator = " [CLOSE_MATCH]"

                        print(f"  - {source_indicator} {pkg_name} (using v{version_used}, malicious: {malicious_str}){match_indicator}")
                    else:
                        print(f"  - {source_indicator} {pkg_name}")
                else:
                    print(f"  - {pkg_name}")

    print("\nResults saved to: analysis_results.json and projects_list.json")


def build_stats_from_package_stats(package_stats: Dict, packages_lookup: Dict) -> Dict:
    """Build the stats structure from package_stats for saving."""
    total_projects_any_version = {}  # uuid -> name
    total_projects_exact_version = {}  # uuid -> name
    total_projects_major_version = {}  # uuid -> name
    packages_with_projects = 0
    package_details = []

    for package_name, pkg_stats in package_stats.items():
        any_version_dict = pkg_stats['projects_any_version']  # uuid -> {name, version}
        exact_version_dict = pkg_stats['projects_exact_version']  # uuid -> {name, version}
        major_version_dict = pkg_stats['projects_major_version']  # uuid -> {name, version}

        if any_version_dict:
            packages_with_projects += 1
            # Update total projects (extract names)
            total_projects_any_version.update({uuid: info['name'] for uuid, info in any_version_dict.items()})
            total_projects_exact_version.update({uuid: info['name'] for uuid, info in exact_version_dict.items()})
            total_projects_major_version.update({uuid: info['name'] for uuid, info in major_version_dict.items()})

            package_info = packages_lookup[package_name]

            # Build project lists with names and versions
            projects_any = [{'uuid': uuid, 'name': info['name'], 'version': info['version']} for uuid, info in any_version_dict.items()]
            projects_exact = [{'uuid': uuid, 'name': info['name'], 'version': info['version']} for uuid, info in exact_version_dict.items()]
            projects_major = [{'uuid': uuid, 'name': info['name'], 'version': info['version']} for uuid, info in major_version_dict.items()]

            package_details.append({
                'package': package_name,
                'version': package_info['version_str'],
                'major_version': package_info['major_version'],
                'malicious_versions': package_info['malicious_versions'],
                'all_versions_malicious': package_info.get('all_versions_malicious', False),
                'source': package_info.get('source', 'Unknown'),
                'projects_any_version': {
                    'count': len(any_version_dict),
                    'projects': projects_any
                },
                'projects_exact_version': {
                    'count': len(exact_version_dict),
                    'projects': projects_exact
                },
                'projects_major_version': {
                    'count': len(major_version_dict),
                    'projects': projects_major
                }
            })

    return {
        'total_packages': len(packages_lookup),
        'packages_with_projects': packages_with_projects,
        'total_projects_any_version': total_projects_any_version,
        'total_projects_exact_version': total_projects_exact_version,
        'total_projects_major_version': total_projects_major_version,
        'package_details': package_details
    }


def save_results(stats: Dict, current_idx: int, total_projects: int, final: bool = False):
    """Save results incrementally to JSON files."""
    # Use /app/output if it exists (Docker volume mount), otherwise current directory
    output_dir = '/app/output' if os.path.exists('/app/output') else '.'

    # Save detailed results to JSON
    output_data = {
        'summary': {
            'total_packages': stats['total_packages'],
            'projects_processed': current_idx,
            'packages_with_projects': stats['packages_with_projects'],
            'projects_any_version': len(stats['total_projects_any_version']),
            'projects_exact_version': len(stats['total_projects_exact_version']),
            'projects_major_version': len(stats['total_projects_major_version'])
        },
        'package_details': stats['package_details']
    }

    output_file = os.path.join(output_dir, 'analysis_results.json')
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    # Save project lists
    # Build projects output with names
    projects_output = {
        'projects_any_version': [{'uuid': uuid, 'name': name} for uuid, name in stats['total_projects_any_version'].items()],
        'projects_exact_version': [{'uuid': uuid, 'name': name} for uuid, name in stats['total_projects_exact_version'].items()],
        'projects_major_version': [{'uuid': uuid, 'name': name} for uuid, name in stats['total_projects_major_version'].items()]
    }

    projects_file = os.path.join(output_dir, 'projects_list.json')
    with open(projects_file, 'w') as f:
        json.dump(projects_output, f, indent=2)

    if not final:
        print(f"  💾 Progress saved ({current_idx}/{total_projects} projects processed)")


if __name__ == "__main__":
    main()

