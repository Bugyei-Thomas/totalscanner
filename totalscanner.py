import hashlib
import requests
import sys

# your virustotal api key here
API_KEY = 'your_virustotal_api_key'

# function to hash the file with sha256
def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            # read file in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

# function to check the hash on virustotal
def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': API_KEY, 'resource': file_hash}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            return json_response
        else:
            print("Hash not found in VirusTotal.")
            return None
    else:
        print(f"Error: {response.status_code}")
        return None

def main(file_path):
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA256): {file_hash}")
    
    vt_result = check_virustotal(file_hash)
    
    if vt_result:
        print("VirusTotal scan results:")
        print(f"  Detection Ratio: {vt_result['positives']}/{vt_result['total']}")
        print(f"  Scan Date: {vt_result['scan_date']}")
        print(f"  Permalink: {vt_result['permalink']}")
    else:
        print("No match found on VirusTotal.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)

