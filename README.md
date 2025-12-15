# Advanced SQL Injection Scanner 🔍

A professional-grade SQL injection vulnerability scanner with recursive crawling capabilities. Designed for penetration testers, security engineers, and bug bounty hunters.

## Features ✨

- **Recursive Web Crawling**: Automatically discovers all pages within target domain
- **Advanced SQLi Detection**: Tests for error-based SQL injection across multiple DBMS
- **Multi-Threaded Scanning**: Concurrent scanning for improved performance
- **Smart Error Handling**: Resilient to network failures and timeouts
- **Real-time Reporting**: Color-coded terminal output with instant feedback
- **Comprehensive Reports**: JSON export with detailed vulnerability findings
- **Database Fingerprinting**: Identifies MySQL, PostgreSQL, Oracle, and MSSQL

## Installation 📦

# Clone the repository
git clone https://github.com/yourusername/advanced-sql-scanner.git

cd advanced-sql-scanner

-d, --domain      Target domain to scan (required)
--max-depth       Maximum crawl depth (default: 10)
--threads         Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 30)
--verify-ssl      Verify SSL certificates (default: False)
--user-agent      Custom User-Agent string
--log-level       Logging level [DEBUG|INFO|WARNING|ERROR]

# Install dependencies
pip install -r requirements.txt

### 1. Simple Scan

python sql_scanner.py -d testphp.vulnweb.com
