import os, re, json, time, requests
from playwright.sync_api import sync_playwright

CVE_DIR = os.path.join(os.path.dirname(__file__), '..', 'cvelistV5', 'cves')

def fetch_references(data: dict) -> tuple[list, list]:
    """
    Fetches the patch commit URLs from the list of URLs.
    """
    references = data['containers']['cna']['references'] if 'references' in data['containers']['cna'] else []
    if not references:
        return [], []
    
    git_re = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)' # Used this regex from CVEfixes (https://github.com/secureIT-project/CVEfixes)
    patch_commit_data = []
    other_urls = []

    for ref in references:
        match = re.search(git_re, ref['url'])
        if match:
            patch_commit_data.append({
                'owner': match.group('owner'),
                'project': match.group('project'),
                'hash': match.group('hash'),
                'repo_url': match.group('repo').replace(r'http:', r'https:'),
                'patch_commit_url': ref['url']
            })
        else:
            other_urls.append(ref['url'])
    
    return patch_commit_data, other_urls

def get_cwe_info(data: dict) -> list[dict]:
    # [{'id': cwe['cweId'], 'value': cwe['value']} if 'cweId' in cwe else {'id': 'n/a', 'value': cwe['value']} for cwe in cve['problemtype']['problemtype_data'][0]['description']] if 'problemtype' in cve else []
    cwes = []
    problem_types = data['containers']['cna']['problemTypes'] if 'problemTypes' in data['containers']['cna'] else []
    for problem_type in problem_types:
        if 'descriptions' in problem_type:
            for description in problem_type["descriptions"]:
                if 'type' in description and description["type"].lower() != "cwe":
                    continue
                if 'lang' in description and description["lang"].lower() != "en":
                    continue
            
            cwe_info = {'id': 'not provided', 'value': 'not provided'}
            if "cweId" in description:
                cwe_info['id'] = description["cweId"]
            elif "description" in description:
                cwe_re = re.search(r'CWE-(\d+)', description["value"])
                if cwe_re:
                    cwe_info['id'] = cwe_re.group(1)
            cwe_info['value'] = description["description"] if "description" in description else "not provided"
            cwes.append(cwe_info)

    return cwes

def get_version_info(data: dict) -> tuple[str, str]:
    vendor_data = data["containers"]["cna"]["affected"] if "affected" in data["containers"]["cna"] else []
    for vendor in vendor_data:
        if 'versions' in vendor:
            for version in vendor['versions']:
                if 'status' in version and version['status'].lower() != 'affected':
                    continue
                if 'lessThan' in version:
                    return version['lessThan'], 'lessThan'
                elif 'lessThanOrEqual' in version:
                    return version['lessThanOrEqual'], 'lessThanOrEqual'
                else:
                    invalid_versions = ['unspecified', '*', '0']
                    if 'version' in version and version['version'] not in invalid_versions:
                        return version['version'], 'equal'
    return 'n/a', 'n/a'

def process_cve_data(data: dict) -> dict:
    """
    Processes the CVE data and returns a dictionary.
    """
    cve_data = {}
    
    # cve id
    if 'cveMetadata' not in data or 'cveId' not in data["cveMetadata"]:
        return {}
    cve_data['id'] = data["cveMetadata"]["cveId"]

    # check if containers are present
    if 'containers' not in data or 'cna' not in data["containers"]:
        return cve_data

    # description
    descriptions = data["containers"]["cna"]["descriptions"] if "descriptions" in data["containers"]["cna"] else []
    descriptions = [desc["value"] for desc in descriptions if desc["lang"] == "en"] if descriptions else []
    cve_data['description'] = descriptions[0] if descriptions else ""

    # published date
    cve_data['published_date'] = data["cveMetadata"]["datePublished"] if "datePublished" in data["cveMetadata"] else ""

    # cwes
    cve_data['cwes'] = get_cwe_info(data)

    # patch and other urls
    patch_urls, other_urls = fetch_references(data)

    if not len(patch_urls):
        return cve_data
    cve_data['patch_urls'] = patch_urls
    cve_data['other_urls'] = other_urls

    # version
    version, version_type = get_version_info(data)
    if version != 'n/a' and version_type != 'n/a':
        cve_data['version_data'] = {
            'version': version,
            'version_type': version_type
        }
    else:
        cve_data['version_data'] = {}

    return cve_data

def get_cve_by_id(cve_id: str) -> dict | None:
    """
    Returns the CVE data for the given CVE ID.
    """
    if not cve_id.startswith("CVE-") or len(cve_id.split('-')) != 3:
        raise ValueError("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNNNN")
    
    # Extract year and numeric portion from the CVE ID
    _, year, number = cve_id.split('-')
    year = int(year)
    number = int(number)
    
    # Calculate the subdirectory
    sub_dir = f"{year}/{number // 1000}xxx"
    
    # Construct the full file path
    file_path = os.path.join(CVE_DIR, sub_dir, f"{cve_id}.json")

    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as f:
            cve_data = json.load(f)
        return process_cve_data(cve_data)
    else:
        print(f"{file_path} does not exist")
        return None

def affected_version_exist(repo_owner: str, repo_name: str, version: str, version_type: str) -> str:
    headers = {
        "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
        "Accept": "application/vnd.github.v3+json"
    }
    tag = ""
    # 1) First check for equality
    if 'equal' in version_type.lower():
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/ref/tags/v{version}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            tag = version
        else:
            print(f"v{version} does not exist as a tag. Error: {response.status_code}, {response.text}")
            print(f"Checking if {version} exists as a tag...")
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/ref/tags/{version}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                tag = version
            else:
                print(f"Error: {response.status_code}, {response.text}")
    # 2) If not found, check for less than
    if not tag and 'lessThan' in version_type:
        page = 1
        found = False
        while True:
                url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/tags"
                params = {
                    "per_page": 100,  # Max allowed per page
                    "page": page
                }
                response = requests.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    tags = response.json()
                    if not tags:
                        break
                    for tag_info in tags:
                        if found:
                            tag = tag_info["name"]
                            break
                        if tag_info["name"] == version or tag_info["name"] == f"v{version}":
                            found = True
                    page += 1
                else:
                    print(f"Error: {response.status_code}, {response.text}")
                    break
    
    return tag

def get_commit_data(repo_owner: str, repo_name: str, commit_hash: str) -> dict | None:
    """
    Fetches commit data from the GitHub API.
    """
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{commit_hash}"
    headers = {
        "Authorization": f"token {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = None
    while True:
        response = requests.get(url, headers=headers)

        if response.status_code == 403:
            print("Rate limit exceeded. Waiting for 60 seconds...")
            time.sleep(60)
        else:
            break
    
    # 1) Check if commits still exist and their information can be extracted
    if response.status_code == 200:
        commit_data = response.json()
        data = None
        
        # 2) Collect file changes
        data = {
            'url': commit_data['html_url'],
            'msg': commit_data['commit']['message'],
            'file_patch': []
        }
        for file in commit_data['files']:
            file_patch = {
                'file_name': file['filename'],
                'hunks': []
            }
            if 'patch' in file:
                patches = file['patch'].split('@@')
                patches_ix = [i for i in range(2, len(patches), 2)]
                for ix in patches_ix:
                    file_patch['hunks'].append({
                        'header': '@@' + patches[ix-1] + '@@',
                        'patch': patches[ix].strip(),
                    })
            data['file_patch'].append(file_patch)
        return data
    else:
        print("Failed to fetch commit data. Status Code:", response.status_code)
        return None

def get_patch_content(owner: str, project: str, hash: str) -> str | None:
    patch_data = get_commit_data(owner, project, hash)
    if patch_data:
        patch_content = patch_data['msg']+'\n'+'\n'.join(['\nFilename: '+file['file_name']+':\n```\n'+'\n\n'.join([hunk['header']+'\n'+hunk['patch'] for hunk in file['hunks']])+'\n```' for file in patch_data['file_patch']])
        return patch_content
    return None

def scrape(url: str) -> str | None:
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    content = None
    try:
        page.goto(url)
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception as e:
            print(f"Error waiting for load state: {e}")
        content = page.locator("body").inner_text()
        if "sign in" in content.lower() and len(content) < 500:
            print(f"Error: {url} is a sign in page")
            content = None
    except Exception as e:
        print(f"Error: {url} has this error: {e}")
        content = None
    finally:
        browser.close()
        playwright.stop()
    return content