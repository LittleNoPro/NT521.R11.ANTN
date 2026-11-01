# CVE Data

To run CVE-Genie the extracted data `<json-file-path>` should look like this:

```json
{  
    "CVE-202X-XXXX": {
        "description": "... (REQUIRED)",
        "cwe": [
            {
                "id": "CWE-XXX (Optional)",
                "value": "... (Optional)"
            }
        ],
        "patch_commits": [
            {
                "url": "https://github.com/<owner>/<repo_name>/commit/<hash> (Optional)",
                "content": "... (Optional)"
            }
        ],
        "sw_version": "... (REQUIRED)",
        "sw_version_wget": "https://github.com/<owner>/<repo_name>/archive/refs/tags/<sw_version>.zip (REQUIRED)",
        "sec_adv": [
            {
                "url": "https://github.com/advisories/XXXXXX (Optional)",
                "content": "... (Optional)"
            }
        ]
    }
}
```
