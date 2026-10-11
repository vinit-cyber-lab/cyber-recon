#!/usr/bin/env python3
"""
CyberNox - Async Web Reconnaissance Suite
Sirf wahi target scan karein jo aapki ownership mein hai ya jiske liye
aapke paas likhit permission hai (jaise apni lab machine ya DVWA).
"""
import asyncio
import argparse
import json
import socket
import sys
from datetime import datetime

import aiohttp
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""{Fore.CYAN}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗██████╗ ██╗  ██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔══██╗╚██╗██╔╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║  ██║ ╚███╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██║  ██║ ██╔██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║██████╔╝██╔╝ ██╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
{Fore.YELLOW}        [ Async Web Reconnaissance Suite ]
{Style.RESET_ALL}"""

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 8443]
WORDLIST = ["admin", "login", "dashboard", "api", "backup", "config",
            "phpmyadmin", "robots.txt"]
SECURITY_HEADERS = ["X-Frame-Options", "X-Content-Type-Options",
                    "Strict-Transport-Security", "Content-Security-Policy"]


def confirm_authorization(target: str) -> None:
    """Scan se pehle user se confirmation lo."""
    print(f"{Fore.YELLOW}[!] Target: {target}")
    print(f"{Fore.YELLOW}[!] Kya aap confirm karte hain ki yeh aapki ownership mein hai")
    print(f"{Fore.YELLOW}    ya aapke paas explicit permission hai? (yes/no)")
    if input("> ").strip().lower() not in ("yes", "y", "haan"):
        print(f"{Fore.RED}[-] Scan cancel kiya gaya.")
        sys.exit(0)


class CyberNoxRecon:
    def __init__(self, target, threads=20, timeout=5, output=None):
        self.target = target.replace("https://", "").replace("http://", "").strip("/")
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.ip = None
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "ip": None,
            "open_ports": [],
            "directories": [],
            "security_headers": {},
        }

    def resolve_ip(self) -> str:
        try:
            self.ip = socket.gethostbyname(self.target)
            self.results["ip"] = self.ip
            print(f"{Fore.GREEN}[+] Target IP resolved: {self.ip}")
            return self.ip
        except socket.gaierror:
            print(f"{Fore.RED}[-] Domain resolve nahi hua: {self.target}")
            sys.exit(1)

    async def _check_port(self, semaphore, port):
        async with semaphore:
            loop = asyncio.get_running_loop()
            try:
                # Blocking connect ko thread pool mein chalao
                is_open = await asyncio.wait_for(
                    loop.run_in_executor(None, self._tcp_connect, port),
                    timeout=self.timeout + 1,
                )
                if is_open:
                    print(f"{Fore.GREEN}[+] OPEN PORT: {port}")
                    self.results["open_ports"].append(port)
            except asyncio.TimeoutError:
                pass

    def _tcp_connect(self, port) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            return s.connect_ex((self.ip, port)) == 0

    async def scan_ports(self):
        print(f"\n{Fore.CYAN}[*] Port scan shuru ho raha hai...")
        semaphore = asyncio.Semaphore(self.threads)
        await asyncio.gather(*(self._check_port(semaphore, p) for p in COMMON_PORTS))
        self.results["open_ports"].sort()

    async def _check_path(self, session, semaphore, scheme, word):
        async with semaphore:
            url = f"{scheme}://{self.target}/{word}"
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 403):
                        color = Fore.GREEN if resp.status == 200 else Fore.YELLOW
                        print(f"{color}[FOUND] /{word} -> {resp.status}")
                        self.results["directories"].append(
                            {"path": word, "status": resp.status, "url": url}
                        )
                        return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            return False

    async def check_paths_and_headers(self, session):
        print(f"\n{Fore.CYAN}[*] Common paths check ho rahe hain...")
        semaphore = asyncio.Semaphore(self.threads)

        # HTTPS pehle try karo, nahi to HTTP
        scheme = "https"
        try:
            async with session.get(f"https://{self.target}", timeout=self.timeout) as resp:
                headers = resp.headers
        except (aiohttp.ClientError, asyncio.TimeoutError):
            scheme = "http"
            try:
                async with session.get(f"http://{self.target}", timeout=self.timeout) as resp:
                    headers = resp.headers
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f"{Fore.RED}[-] Website se connect nahi ho paya: {e}")
                return

        await asyncio.gather(
            *(self._check_path(session, semaphore, scheme, w) for w in WORDLIST)
        )

        print(f"\n{Fore.CYAN}[*] Security headers check ho rahe hain...")
        for header in SECURITY_HEADERS:
            if header in headers:
                print(f"{Fore.GREEN}[+] {header}: Configured")
                self.results["security_headers"][header] = "Present"
            else:
                print(f"{Fore.RED}[-] {header}: MISSING")
                self.results["security_headers"][header] = "Missing"

    async def run(self):
        print(BANNER)
        self.resolve_ip()
        await self.scan_ports()

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            await self.check_paths_and_headers(session)

        if self.output:
            with open(self.output, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Results saved: {self.output}")


def main():
    parser = argparse.ArgumentParser(description="CyberNox - Web Recon Suite")
    parser.add_argument("-t", "--target", required=True,
                        help="Target domain ya IP (sirf apni lab/permitted target)")
    parser.add_argument("-o", "--output", help="JSON report file (e.g. report.json)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Concurrent tasks (default: 20)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Timeout seconds (default: 5)")
    parser.add_argument("--yes", action="store_true",
                        help="Authorization prompt skip karein (sirf automation ke liye)")
    args = parser.parse_args()

    if not args.yes:
        confirm_authorization(args.target)

    scanner = CyberNoxRecon(args.target, threads=args.threads,
                            timeout=args.timeout, output=args.output)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
