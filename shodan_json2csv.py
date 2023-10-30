import json
import csv
import re
import socket
import struct

# Define a function to convert an integer IP to a human-readable format
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

# Define a function to extract NTLM Info fields
def extract_ntlm_fields(ntlm_info):
    fields = {
        "OS": None,
        "OS Build": None,
        "Target Name": None,
        "NetBIOS Domain Name": None,
        "NetBIOS Computer Name": None,
        "DNS Domain Name": None,
        "FQDN": None
    }

    # Use regular expressions to extract each field
    for field_name, pattern in fields.items():
        match = re.search(f"{field_name}: (.+)", ntlm_info)
        if match:
            fields[field_name] = match.group(1)

    return fields

# Define a function to extract specific data from the JSON and write it to a CSV row
def extract_and_write_to_csv(data, csv_writer):
    ip = int_to_ip(data.get("ip", 0))  # Convert IP from integer to human-readable
    port = data.get("port", "")
    city = data.get("location", {}).get("city", "")
    country = data.get("location", {}).get("country_name", "")
    org = data.get("org", "")
    os = data.get("os", "")
    
    # Process hostnames
    hostnames = ", ".join(data.get("hostnames", []))

    # Process vulnerabilities
    vulnerabilities = data.get("vulns", {})
    cves = ", ".join(vuln for vuln in vulnerabilities.keys())

    # Extract ISP data
    isp = data.get("isp", "")

    # Extract the "data" field and get NTLM Info
    ntlm_info = data.get("data", "")

    # Extract "product" field
    product = data.get("product", "")

    # Extract NTLM Info fields
    ntlm_fields = extract_ntlm_fields(ntlm_info)

    # Write the data to the CSV row
    csv_writer.writerow([ip, port, city, country, org, os, hostnames, cves, isp, product] + list(ntlm_fields.values()))

# Define file paths
json_file_path = "cleaned.json"
csv_file_path = "shodan_data.csv"

# Open the JSON file for reading and CSV file for writing
with open(json_file_path, "r") as json_file, open(csv_file_path, "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    
    # Write CSV headers
    csv_writer.writerow(["IP Address", "Port", "City", "Country", "Organization", "Operating System", "Hostnames", "CVEs", "ISP", "Product", "OS", "OS Build", "Target Name", "NetBIOS Domain Name", "NetBIOS Computer Name", "DNS Domain Name", "FQDN"])

    for line in json_file:
        try:
            data = json.loads(line)
            extract_and_write_to_csv(data, csv_writer)
        except json.JSONDecodeError:
            print("Error decoding JSON line")

print(f"Data has been exported to {csv_file_path}.")
