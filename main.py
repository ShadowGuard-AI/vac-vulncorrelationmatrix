import argparse
import logging
import json
import requests
from bs4 import BeautifulSoup
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants (API endpoints, etc.) - Consider moving to a config file
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # Example
CVE_DETAILS_BASE_URL = "https://www.cvedetails.com/cve/" # Example


class VulnCorrelationMatrix:
    """
    Generates a correlation matrix based on vulnerability metadata.
    Aggregates data from NVD, CVE Details, and (potentially) Exploit-DB.
    """

    def __init__(self, cve_ids=None,  nvd_api_key=None):
        """
        Initializes the VulnCorrelationMatrix object.

        Args:
            cve_ids (list, optional): A list of CVE IDs to analyze. Defaults to None.
            nvd_api_key (str, optional): NVD API Key. Defaults to None.
        """
        self.cve_ids = cve_ids if cve_ids else []
        self.nvd_api_key = nvd_api_key
        self.vulnerability_data = {}  # Store aggregated vulnerability data
        self.correlation_matrix = defaultdict(lambda: defaultdict(int))  # Use defaultdict

    def fetch_nvd_data(self, cve_id):
        """
        Fetches vulnerability data from the NVD API for a given CVE ID.

        Args:
            cve_id (str): The CVE ID to fetch data for.

        Returns:
            dict: A dictionary containing relevant vulnerability data from NVD, or None if an error occurs.
        """
        try:
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
            logging.info(f"Fetching NVD data for {cve_id} from {url}")
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            if data and data['resultsPerPage'] > 0 and data['vulnerabilities']:
                return data['vulnerabilities'][0]['cve']
            else:
                logging.warning(f"No NVD data found for {cve_id}")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching NVD data for {cve_id}: {e}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding NVD JSON response for {cve_id}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching NVD data for {cve_id}: {e}")
            return None

    def fetch_cve_details_data(self, cve_id):
        """
        Fetches vulnerability data from CVE Details for a given CVE ID.

        Args:
            cve_id (str): The CVE ID to fetch data for.

        Returns:
            dict: A dictionary containing relevant vulnerability data from CVE Details, or None if an error occurs.
        """
        try:
            url = f"{CVE_DETAILS_BASE_URL}{cve_id}"
            logging.info(f"Fetching CVE Details data for {cve_id} from {url}")
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extract relevant information using BeautifulSoup
            cvss_score_element = soup.find('div', class_='cvssbox')
            cvss_score = float(cvss_score_element.text.strip()) if cvss_score_element else None

            affected_products = []
            product_table = soup.find('table', id='vulnprodstable')
            if product_table:
                for row in product_table.find_all('tr')[1:]:  # Skip header row
                    cells = row.find_all('td')
                    if len(cells) >= 4:
                        vendor = cells[0].text.strip()
                        product = cells[1].text.strip()
                        version = cells[2].text.strip()
                        affected_products.append({'vendor': vendor, 'product': product, 'version': version})

            data = {
                'cvss_score': cvss_score,
                'affected_products': affected_products
            }

            return data

        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching CVE Details data for {cve_id}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching CVE Details data for {cve_id}: {e}")
            return None


    def aggregate_vulnerability_data(self):
        """
        Aggregates vulnerability data from various sources for each CVE ID.
        """
        for cve_id in self.cve_ids:
            self.vulnerability_data[cve_id] = {}
            nvd_data = self.fetch_nvd_data(cve_id)
            cve_details_data = self.fetch_cve_details_data(cve_id)


            if nvd_data:
                self.vulnerability_data[cve_id].update(nvd_data)
            if cve_details_data:
                self.vulnerability_data[cve_id].update(cve_details_data)



            logging.debug(f"Aggregated data for {cve_id}: {self.vulnerability_data[cve_id]}")

    def correlate_vulnerabilities(self):
        """
        Correlates vulnerabilities based on common metadata (e.g., affected software, CWE).
        """
        cve_ids = list(self.vulnerability_data.keys())

        for i in range(len(cve_ids)):
            for j in range(i + 1, len(cve_ids)):  # Avoid comparing CVEs with themselves and duplicate comparisons
                cve1 = cve_ids[i]
                cve2 = cve_ids[j]

                # Example: Correlate based on affected products
                if 'affected_products' in self.vulnerability_data[cve1] and 'affected_products' in self.vulnerability_data[cve2]:
                    products1 = self.vulnerability_data[cve1]['affected_products']
                    products2 = self.vulnerability_data[cve2]['affected_products']
                    common_products = [p for p in products1 if p in products2]  # Simple check

                    if common_products:
                        self.correlation_matrix[cve1][cve2] += 1
                        self.correlation_matrix[cve2][cve1] += 1
                        logging.info(f"Correlation found between {cve1} and {cve2} based on common products.")

                # Example: Correlate based on CWE
                if 'cwe' in self.vulnerability_data[cve1] and 'cwe' in self.vulnerability_data[cve2]:
                    cwe1 = self.vulnerability_data[cve1]['cwe']['name']  # Assuming CWE name is what we want. May need parsing.
                    cwe2 = self.vulnerability_data[cve2]['cwe']['name']
                    if cwe1 == cwe2:
                        self.correlation_matrix[cve1][cve2] += 1
                        self.correlation_matrix[cve2][cve1] += 1
                        logging.info(f"Correlation found between {cve1} and {cve2} based on common CWE {cwe1}.")


    def generate_report(self, output_format="text"):
        """
        Generates a report of the correlation matrix and ranked vulnerabilities.

        Args:
            output_format (str, optional): The format of the report (e.g., "text", "json"). Defaults to "text".

        Returns:
            str: The generated report.
        """
        if output_format == "text":
            report = "Vulnerability Correlation Matrix:\n"
            for cve1, correlations in self.correlation_matrix.items():
                report += f"\n{cve1}:\n"
                for cve2, count in correlations.items():
                    report += f"  - {cve2}: {count}\n"
        elif output_format == "json":
            report = json.dumps(self.correlation_matrix, indent=4)
        else:
            logging.error(f"Invalid output format: {output_format}.  Returning text format.")
            report = "Invalid Output Format Selected" # Or raise an Exception


        # (Placeholder) Add Vulnerability Ranking (Based on CVSS, exploit availability, etc.)
        # Could also add report sections with other metrics.

        return report


def setup_argparse():
    """
    Sets up the argparse argument parser.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="vac-VulnCorrelationMatrix: Vulnerability Aggregation and Correlation Tool")
    parser.add_argument("-c", "--cve", nargs='+', help="List of CVE IDs to analyze (e.g., CVE-2023-1234 CVE-2023-5678)")
    parser.add_argument("-o", "--output", default="text", choices=["text", "json"], help="Output format (text or json)")
    parser.add_argument("-n", "--nvd_api_key", help="NVD API Key (optional)")
    parser.add_argument("-f", "--cve_file", help="File containing a list of CVE IDs (one per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    return parser


def main():
    """
    Main function to execute the vulnerability correlation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cve_ids = []
    if args.cve:
        cve_ids = args.cve
    elif args.cve_file:
        try:
            with open(args.cve_file, 'r') as f:
                cve_ids = [line.strip() for line in f if line.strip()] # remove empty lines
        except FileNotFoundError:
            logging.error(f"CVE file not found: {args.cve_file}")
            return
        except Exception as e:
            logging.error(f"Error reading CVE file: {e}")
            return
    else:
        print("Error: No CVE IDs provided.  Please use -c or -f to specify CVEs.")
        return


    # Input validation: basic CVE ID format check
    invalid_cves = [cve for cve in cve_ids if not cve.startswith("CVE-")]
    if invalid_cves:
        logging.error(f"Invalid CVE IDs found: {invalid_cves}.  Please ensure CVE IDs start with 'CVE-'.")
        return




    try:
        correlation_matrix = VulnCorrelationMatrix(cve_ids=cve_ids, nvd_api_key=args.nvd_api_key)
        correlation_matrix.aggregate_vulnerability_data()
        correlation_matrix.correlate_vulnerabilities()
        report = correlation_matrix.generate_report(output_format=args.output)
        print(report)

    except Exception as e:
        logging.exception("An unexpected error occurred during processing:")  # Print full traceback



if __name__ == "__main__":
    main()


# Example Usage (from the command line):
# 1.  Analyze specific CVEs and output to text:
#     python main.py -c CVE-2023-46604 CVE-2023-20177
# 2.  Analyze CVEs from a file (cve_list.txt) and output to JSON:
#     python main.py -f cve_list.txt -o json
# 3.  Use an NVD API key (if you have one):
#     python main.py -c CVE-2023-46604 -n YOUR_NVD_API_KEY
# 4.  Enable verbose logging:
#     python main.py -c CVE-2023-46604 -v