# TotalScanner

A Python tool for scanning files against VirusTotal. Computes the SHA-256 hash of a file and queries the VirusTotal API to retrieve detection results.

## Requirements

- Python 3
- requests
- VirusTotal API key

## Installation

```bash
git clone https://github.com/s4wbvnny/totalscanner
cd totalscanner
pip3 install -r requirements.txt
```

## Usage

Set your VirusTotal API key as an environment variable:

```bash
export VT_API_KEY="your_virustotal_api_key"
```

Then run:

```bash
python3 totalscanner.py <path/to/file>
```

## How It Works

1. Computes the SHA-256 hash of the specified file.
2. Queries the VirusTotal API with the hash.
3. Displays detection ratio, scan date, and permalink if a match is found.

## License

MIT
