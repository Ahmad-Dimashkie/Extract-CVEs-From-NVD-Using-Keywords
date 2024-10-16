# CVE Search Script

================================================

This script allows you to search for Common Vulnerabilities and Exposures (CVEs) related to AI/ML topics using the NVD API. It extracts CVEs from an Excel file and retrieves additional information about vulnerabilities based on predefined keywords.

## Features

---

- Extracts existing CVEs from an Excel file.
- Searches the NVD database for CVEs related to AI/ML keywords.
- Retrieves and displays CVSS scores, descriptions, and suggested mitigations.
- Exports the results to a JSON file for easy access.

## Requirements

---

- Python 3.7 or later
- Libraries: `nvdlib`, `pandas`, `torch`, `json`

You can install the required libraries using pip:

```bash
pip install nvdlib pandas torch
```

### Usage

---

#### Prepare your Excel File

Create an Excel file named CVEs.xlsx with the CVEs you want to check in the first column. Save it in the same directory as the script.

#### Set Your NVD API Key

Obtain an API key from the National Vulnerability Database (NVD) if you don’t have one. Replace 'your-api-key' in the script with your actual API key.

#### Run the Script

Execute the script in your terminal or command prompt:

```bash
python CVEs.py
```

#### Check the Results

After running the script, you will find a file named cve_results.json in the same directory. This file contains the search results, including CVE numbers, attack types, summaries, CVSS scores, severities, related keywords, and mitigation information.

### Code Overview

---

- `extract_cves_from_excel(file_path)`: Loads CVEs from an Excel file.
- `get_mitigation(cve)`: Retrieves mitigation information for a CVE (currently a placeholder).
- `get_cvss_score(cve)`: Returns the CVSS score and severity for a CVE.
- `infer_attack_type(description, keyword)`: Infers the type of attack based on the CVE description and keyword.
- `search_cves_by_keywords(keywords, cve_file_path, api_key)`: Main function to search for CVEs using specified keywords.

### Customization

---

You can modify the keywords list in the script to include other topics or specific terms you want to search for.
