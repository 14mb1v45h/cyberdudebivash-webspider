# cyberdudebivash webspider

A versatile web spider tool built in Python, designed for ethical web crawling with cybersecurity-focused features. It supports CLI, GUI, and API interfaces for scripted use.

## Description

This tool crawls websites recursively up to a specified depth, extracts links and forms, and performs basic security checks (e.g., missing headers, potential XSS patterns). It respects robots.txt for ethical use (default, with ignore option) and includes user-agent spoofing. Now with realtime logging using Python's logging module for monitoring crawl progress and errors.

**Note:** Use only on sites you have permission to crawl. Misuse may be illegal. Ignoring robots.txt should be done only with explicit permission.

## Features

- **Crawling**: Recursive link extraction (same domain).
- **Cybersecurity Checks**: Missing security headers, potential stored XSS, password forms.
- **Ethical Controls**: Robots.txt respect (default); option to ignore.
- **Logging**: Realtime console/file logging with levels (INFO/DEBUG); integrated in all modes.
- **Interfaces**:
  - CLI: Scripted/automation.
  - GUI: Interactive via Tkinter, logs to output.
  - API: HTTP server for remote queries, logs to console.
- **Output**: JSON with URLs, links, forms, vulns, headers.

## Installation

1. Python 3.8+ required.
2. Download `cyberdudebivash_webspider.py`.
3. No dependencies—all built-in (including logging).

Optional virtual env:

python -m venv venv
source venv/bin/activate  # Unix/Mac
venv\Scripts\activate  # Windows




## Usage

`python cyberdudebivash_webspider.py [cli|gui|api]`

### CLI
`python cyberdudebivash_webspider.py cli --url https://example.com --depth 2 --output results.json --ignore-robots --log-level DEBUG --log-file spider.log`
- `--url`: Required starting URL.
- `--depth`: Optional max depth (default 2).
- `--output`: Optional JSON output file.
- `--ignore-robots`: Optional flag to ignore robots.txt.
- `--log-level`: Optional (default INFO; e.g., DEBUG for verbose).
- `--log-file`: Optional path to save logs.

### GUI
`python cyberdudebivash_webspider.py gui`
- Input URL/depth, select log level, check "Ignore robots.txt", click Crawl. Logs appear in output realtime.

### API
`python cyberdudebivash_webspider.py api`
- Query: http://localhost:8000/crawl?url=https://example.com&depth=2&ignore_robots=true&log_level=DEBUG (returns JSON; logs to console).

## Limitations

- Static HTML only (no JS rendering—extend with Selenium if needed).
- Basic vuln detection (not full like ZAP).
- No proxies/anti-bot.
- Extend with Scrapy for advanced use.

## Contributing

PRs welcome for enhancements.

## License

MIT. Responsible use only.


## AUTHOR 

BIVASH NAYAK

## COPYRIGHT

copyright @CYBERDUDEBIVASH 2025