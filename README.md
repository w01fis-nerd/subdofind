# Subdomain Finder

A powerful Python-based reconnaissance tool for discovering subdomains of a target domain using multiple enumeration techniques.

## Features

- Multiple Enumeration Methods:
  - DNS Enumeration
  - SSL/TLS Certificate Search
  - Web Scraping
  - Bruteforce Attack
  
- Advanced Capabilities:
  - Asynchronous Processing
  - Certificate Transparency Logs
  - Search Engine Scraping
  - DNS Record Analysis
  - Domain Verification
  - IP Resolution

- Integration with Security Services:
  - Censys Certificate Search
  - Certificate Transparency Logs
  - Multiple Search Engines

- Comprehensive Output:
  - JSON Report Generation
  - Active Subdomain Verification
  - IP Address Resolution
  - Colored Console Output
  - Detailed Logging

## Requirements

- Python 3.7+
- Required Python packages (install via requirements.txt)
- API Keys (optional but recommended):
  - Censys API credentials
  - Shodan API key

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd subdomain_finder
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. (Optional) Configure API keys:
Create a `.env` file in the project directory with your API keys:
```
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
SHODAN_API_KEY=your_shodan_api_key
```

## Usage

Basic usage:
```bash
python subdomain_finder.py -d example.com
```

Specify enumeration methods:
```bash
python subdomain_finder.py -d example.com -m dns cert web bruteforce
```

Available methods:
- `dns`: DNS enumeration
- `cert`: Certificate search
- `web`: Web scraping
- `bruteforce`: Bruteforce subdomain guessing

## Output

The tool generates two types of output:
1. Real-time console output with color-coded information
2. JSON report file in the `results` directory containing:
   - Total subdomains found
   - Active subdomains
   - Resolved IP addresses
   - Timestamp and metadata

Example output file: `results/subdomains_example.com_20240101_120000.json`

## Logging

All operations are logged to `subdomain_finder.log` with detailed information about:
- Enumeration progress
- Errors and exceptions
- API responses
- DNS resolution results

## Security Considerations

- Use this tool only on domains you have permission to test
- Be mindful of rate limiting and API usage
- Some enumeration methods might be detected as scanning activity
- Respect the target's security policies and terms of service

## Advanced Usage

### Custom Wordlist

The tool includes a built-in wordlist of common subdomains. You can modify the `wordlist` variable in the script to add your own entries.

### API Integration

The tool supports integration with various security services:
- Censys: For certificate search
- Certificate Transparency logs
- Search engines (Google, Bing, Yahoo)

### Asynchronous Processing

The tool uses Python's asyncio for efficient processing:
- Concurrent DNS resolution
- Parallel subdomain verification
- Asynchronous HTTP requests

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.



## Disclaimer

This tool is for educational and authorized testing purposes only. The user is responsible for complying with applicable laws and regulations. 
