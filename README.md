# vac-VulnCorrelationMatrix

Generates a correlation matrix based on vulnerability metadata fetched from NVD and CVE Details for operator supplied CVE IDs. Two CVEs correlate when they share an affected product (compared on vendor and product, with version treated as a separate attribute) or a CWE parsed from the NVD v2 weaknesses list. The report ends with a ranked list of the aggregated CVEs ordered by their CVSS scores. It does not use Exploit-DB, does not rank by exploit availability, and does not perform active vulnerability scanning.

A run with no CVE IDs, an invalid CVE ID, an unreadable CVE file, or no data aggregated for any supplied CVE exits non-zero and prints a no data message instead of an empty matrix.

## Install
`git clone https://github.com/ShadowGuard-AI/vac-vulncorrelationmatrix`

## Usage
`python main.py -c CVE-2023-46604 CVE-2023-20177`

## Parameters
- `-h`: Show help message and exit
- `-c`: List of CVE IDs to analyze (e.g., CVE-2023-1234 CVE-2023-5678)
- `-o`: Output format (text or json)
- `-n`: NVD API Key (optional)
- `-f`: File containing a list of CVE IDs (one per line)
- `-v`: Enable verbose logging (DEBUG level)

## License
Copyright (c) ShadowGuard-AI
