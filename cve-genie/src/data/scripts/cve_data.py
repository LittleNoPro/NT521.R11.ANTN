import os
import json
import argparse
from dotenv import load_dotenv
from cve_processor import (
                            affected_version_exist,
                            get_patch_content,
                            get_cve_by_id,
                            scrape
                        )

load_dotenv()

def get_data(cve_id: str, path: str):
    '''
    "CVE-202X-XXXX": {
        "description": "...",
        "cwe": [
            {
                "id": "CWE-XX",
                "value": "CWE-XX ..."
            }
        ],
        "patch_commits": [
            {
                "url": "https://github.com/...",
                "content": "..."
            }
        ],
        "sw_version": "vX.X.X",
        "sw_version_wget": "https://github.com/.../.../archive/refs/tags/vX.X.X.zip",
        "sec_adv": [
            {
                "url": "...",
                "content": "..."
            }
        ]
    }
    '''
    data = {} if not os.path.exists(path) else json.load(open(path))
    software_code_provided = False
    software_version_provided = False
    software_version_available = False
    security_advisories_provided = False

    try:
        cve = get_cve_by_id(cve_id)
        if not cve:
            raise ValueError(f"CVE {cve_id} not found")
        
        data[cve['id']] = {
            "description": cve.get('description'),
            "cwes": cve.get("cwes")
        }

        # 1) source code provided
        patch_commits = [
            {
                "url": patch['patch_commit_url'],
                "content": get_patch_content(patch['owner'], patch['project'], patch['hash'])
            }
            for patch in cve.get('patch_urls')
        ]

        if patch_commits:
            data[cve['id']]["patch_commits"] = patch_commits
            software_code_provided = True
        
        # 2) software version provided
        version_data = cve.get("version_data")
        if version_data:
            software_version_provided = True
        
        # 3) software version available on github
        if version_data:
            patch_urls = cve.get('patch_urls')
            tag = affected_version_exist(
                patch_urls[0]['owner'], 
                patch_urls[0]['project'], 
                version_data['version'], 
                version_data['version_type']
            )
            if tag:
                software_version_available = True
                data[cve['id']]["sw_version"] = tag
                data[cve['id']]["sw_version_wget"] = f"{patch_urls[0]['repo_url']}/archive/refs/tags/{tag}.zip"
        
        # 5) security advisories
        potential_advisories = cve.get("other_urls")
        sec_advs = []
        if potential_advisories:
            keywords = ['security', 'advisory', 'advisories', 'bounties', 'bounty', 'issue', 'issues']
            for url in potential_advisories:
                if url.endswith(('.patch', '.txt', '.pdf', '.zip')):
                    continue
                url_words = url.split('/')
                if any(keyword in url_words for keyword in keywords):
                    sec_adv_content = scrape(url)
                    if sec_adv_content:
                        sec_advs.append({
                            "url": url,
                            "content": sec_adv_content
                        })
        if sec_advs:
            security_advisories_provided = True
        data[cve['id']]["sec_adv"] = sec_advs

        # save data
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"Data for {cve_id} saved to {path}")
        print(f"    - Software code can be obtained from the patch commits (required): {software_code_provided}")
        print(f"    - Software version provided in CVE data (required): {software_version_provided}")
        print(f"    - Software vulnerable version source code available on GitHub (required): {software_version_available}")
        print(f"    - Security advisories provided (Optional): {security_advisories_provided}")

        if software_code_provided and software_version_provided and software_version_available:
            print("✅ Ready to reproduce!!")
        else:
            print("⚠️ Missing required data. Please check the src/data/PROCESSING.md for guidance.")

    except Exception as e:
        print(f"[!] Error processing {cve_id}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get CVE data and save to JSON file.")
    parser.add_argument("--cve_id", type=str, help="CVE ID to process (e.g., CVE-2025-0001)")
    parser.add_argument("--output_path", type=str, help="Path to save the output JSON file")
    args = parser.parse_args()

    get_data(args.cve_id, args.output_path)
