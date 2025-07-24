import urllib.request
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
import argparse
import tkinter as tk
from tkinter import scrolledtext
import http.server
import socketserver
import json
import sys
import re
from queue import Queue
import logging  # Added for logging

class LinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href':
                    link = urljoin(self.base_url, value)
                    self.links.add(link)
        elif tag == 'form':
            action = ''
            for attr, value in attrs:
                if attr == 'action':
                    action = urljoin(self.base_url, value)
            self.forms.append({'action': action})

    def error(self, message):
        pass

class WebSpider:
    def __init__(self, max_depth=2, respect_robots=True):
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.visited = set()
        self.queue = Queue()

    def check_robots(self, url):
        logging.info(f"Checking robots.txt for {url}")
        if not self.respect_robots:
            return True
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            with urllib.request.urlopen(robots_url) as response:
                content = response.read().decode()
                if 'Disallow: /' in content:
                    logging.warning(f"Disallowed by robots.txt: {url}")
                    return False
            return True
        except Exception as e:
            logging.error(f"Error checking robots.txt: {str(e)}")
            return True

    def analyze_page(self, url):
        logging.info(f"Analyzing page: {url}")
        results = {'url': url, 'links': [], 'forms': [], 'vulns': [], 'headers': {}}
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'cyberdudebivash-webspider/1.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8', errors='ignore')
                headers = dict(response.info())
                results['headers'] = headers

                # Basic security checks
                if 'X-Frame-Options' not in headers:
                    results['vulns'].append('Missing X-Frame-Options header (Clickjacking risk)')
                if 'Content-Security-Policy' not in headers:
                    results['vulns'].append('Missing CSP header')
                if re.search(r'<script>alert\(.*\)</script>', content, re.IGNORECASE):
                    results['vulns'].append('Potential stored XSS found')

                parser = LinkParser(url)
                parser.feed(content)
                results['links'] = list(parser.links)
                results['forms'] = parser.forms

                # Basic form vuln check
                for form in results['forms']:
                    if 'password' in content.lower():  # Simplified check
                        results['vulns'].append(f'Potential password form at {form["action"]} (Credential exposure risk)')
                logging.debug(f"Found {len(results['links'])} links and {len(results['forms'])} forms on {url}")
        except Exception as e:
            logging.error(f"Error analyzing {url}: {str(e)}")
            results['error'] = str(e)
        return results

    def crawl(self, start_url, depth=0):
        logging.info(f"Crawling {start_url} at depth {depth}")
        if depth > self.max_depth or start_url in self.visited:
            return []
        if not self.check_robots(start_url):
            return [{'url': start_url, 'error': 'Disallowed by robots.txt'}]

        self.visited.add(start_url)
        results = [self.analyze_page(start_url)]

        for link in results[0].get('links', []):
            if urlparse(link).netloc == urlparse(start_url).netloc:
                results.extend(self.crawl(link, depth + 1))
        logging.info(f"Completed crawl for {start_url}")
        return results

# CLI
def cli():
    parser = argparse.ArgumentParser(description='cyberdudebivash webspider CLI')
    parser.add_argument('--url', required=True, help='Starting URL')
    parser.add_argument('--depth', type=int, default=2, help='Max crawl depth')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--ignore-robots', action='store_true', help='Ignore robots.txt (use ethically)')
    parser.add_argument('--log-level', default='INFO', help='Log level (e.g., INFO, DEBUG)')
    parser.add_argument('--log-file', help='Log file path')
    args = parser.parse_args(sys.argv[2:])

    # Setup logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    spider = WebSpider(max_depth=args.depth, respect_robots=not args.ignore_robots)
    results = spider.crawl(args.url)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
    else:
        print(json.dumps(results, indent=4))

# GUI
def gui():
    root = tk.Tk()
    root.title('cyberdudebivash webspider')

    tk.Label(root, text='URL:').pack()
    url_entry = tk.Entry(root, width=50)
    url_entry.pack()

    tk.Label(root, text='Depth:').pack()
    depth_entry = tk.Entry(root, width=10)
    depth_entry.pack()
    depth_entry.insert(0, '2')

    ignore_var = tk.BooleanVar()
    ignore_check = tk.Checkbutton(root, text='Ignore robots.txt (ethical use only)', variable=ignore_var)
    ignore_check.pack()

    log_level_var = tk.StringVar(value='INFO')
    tk.Label(root, text='Log Level:').pack()
    tk.OptionMenu(root, log_level_var, 'INFO', 'DEBUG').pack()

    output_text = scrolledtext.ScrolledText(root, width=80, height=20)
    output_text.pack()

    class TextHandler(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            output_text.insert(tk.END, msg + '\n')
            output_text.see(tk.END)

    def start_crawl():
        url = url_entry.get()
        depth = int(depth_entry.get())
        ignore = ignore_var.get()
        log_level_str = log_level_var.get()
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)

        # Setup logging
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        text_handler = TextHandler()
        text_handler.setLevel(log_level)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(text_handler)

        spider = WebSpider(max_depth=depth, respect_robots=not ignore)
        results = spider.crawl(url)
        output_text.insert(tk.END, "\n\nCrawl Results:\n" + json.dumps(results, indent=4))

    tk.Button(root, text='Crawl', command=start_crawl).pack()
    root.mainloop()

# API
class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/crawl?'):
            params = dict(q.split('=') for q in self.path[7:].split('&') if q)
            url = params.get('url')
            depth = int(params.get('depth', 2))
            ignore_robots = params.get('ignore_robots', 'false').lower() == 'true'
            log_level_str = params.get('log_level', 'INFO').upper()
            log_level = getattr(logging, log_level_str, logging.INFO)

            # Setup logging (console only for API)
            logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

            if url:
                spider = WebSpider(max_depth=depth, respect_robots=not ignore_robots)
                results = spider.crawl(url)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(results).encode())
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_api(port=8000):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')  # Default for API
    with socketserver.TCPServer(("", port), APIHandler) as httpd:
        logging.info(f'API running on port {port}')
        httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == 'cli':
            cli()
        elif mode == 'gui':
            gui()
        elif mode == 'api':
            run_api()
        else:
            print('Invalid mode. Use: cli, gui, or api')
    else:
        print('Usage: python cyberdudebivash_webspider.py [cli|gui|api]')