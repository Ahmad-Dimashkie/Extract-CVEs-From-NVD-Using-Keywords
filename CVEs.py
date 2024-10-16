import nvdlib
import json
import torch
import pandas as pd

def extract_cves_from_excel(file_path):
    # Load the Excel file and extract the CVEs already seen from the first column
    excel_data = pd.read_excel(file_path)
    cves_list = excel_data.iloc[:, 0].tolist()
    return set(cves_list)

def get_mitigation(cve):
    #Still need to fix this 
    return  'No mitigation information available'

def get_cvss_score(cve):
    try:
        # Using the new score attribute in nvdlib 0.7.0
        if cve.score:
            return cve.score[1], cve.score[2]  # Base score and severity
        else:
            return 'N/A', 'N/A'
    except Exception as e:
        print(f"Error retrieving CVSS score: {e}")
        return 'N/A', 'N/A'

# Define a function to infer attack type from description
def infer_attack_type(description, keyword):
    #Still need to fix this, it should take the description and infer the attack type using an ML model 
    return  keyword + " Attack"

# Define AI/ML-related keywords
keywords = [
    "machine learning", "artificial intelligence", "deep learning", "neural network", "Natural Language Processing", 
    "data science", "PyTorch", "TensorFlow", "Keras", "scikit-learn", "ONNX", "XGBoost", "Machine Learning framework security",
    "machine learning model exploit", "Artificial Intelligence model poisoning", "model inversion attack", "adversarial attack vulnerability",
    "model extraction vulnerability", "inference attack CVE", "data poisoning CVE", "model integrity CVE", 
    "adversarial example", "backdoor attack", "model stealing", "gradient-based attack", "model evasion", 
    "adversarial robustness", "secure Artificial Intelligence model", "model confidentiality", "federated learning security", 
    "differential privacy","model theft"
]

# Function to search CVEs using keywords and avoid duplicates
def search_cves_by_keywords(keywords, cve_file_path, api_key=None, ):
    results = []
    # Initialize the seen_cves set with the provided CVEs
    seen_cves = extract_cves_from_excel(cve_file_path)
    # Set to track unique CVEs
    for keyword in keywords:
        print(f"Searching CVEs for keyword: {keyword}")
        cves = nvdlib.searchCVE(keywordSearch=keyword, key=api_key)
        for cve in cves:
            #print(cve)
            if cve.id not in seen_cves:  # Check for duplicate CVEs
                seen_cves.add(cve.id)  # Add to set of seen CVEs
                description = cve.descriptions[0].value if cve.descriptions else 'No description available'
                attack_type = infer_attack_type(description, keyword)
                score, severity = get_cvss_score(cve)
                mitigation = get_mitigation(cve)
                results.append({
                    'CVE Number': cve.id,
                    'Type of Attack': attack_type,
                    'Summary': description,
                    'CVSS Score': score,
                    'CVSS Severity': severity,
                    'Related Keyword': keyword,
                    'URL': cve.url,
                    'mitigation': mitigation
                })
    return results

# Example usage: Replace 'your_api_key' with your actual NVD API key
cve_file_path = 'CVEs.xlsx'
cve_results = search_cves_by_keywords(keywords, cve_file_path, api_key='your-api-key')

# Save the results to a JSON file
with open('cve_results.json', 'w') as f:
    json.dump(cve_results, f, indent=4)
