import argparse
import asyncio
import json
import re
import socket
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import aiohttp

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            self.links.append(attrs['href'])
        if tag == 'form' and 'action' in attrs:
            self.forms.append({'action': attrs['action'], 'inputs': []})
        if tag == 'input' and self.forms:
            name = attrs.get('name') or attrs.get('id') or 'unnamed'
            self.forms[-1]['inputs'].append(name)
        if tag == 'script' and 'src' in attrs:
            self.links.append(attrs['src'])

class TWReconHunterAsync:
    def __init__(self, target: str, scope_domain: str = None, confirm_scope: bool = False, headers: list = None, deep: bool = False, active: bool = False, discord: str = None, telegram: str = None):
        self.target = target
        self.scope_domain = scope_domain
        self.confirm_scope = confirm_scope
        self.deep = deep
        self.active = active
        self.discord = discord
        self.telegram = telegram
        self.custom_headers = {}
        if headers:
            for h in headers:
                if ':' in h:
                    k, v = h.split(':', 1)
                    self.custom_headers[k.strip()] = v.strip()
        self.parsed = urlparse(target if '://' in target else f'https://{target}')
        self.base_url = f"{self.parsed.scheme or 'https'}://{self.parsed.netloc or self.parsed.path}"
        self.host = self.parsed.netloc or self.parsed.path
        
        self.secrets_regex = {
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            "Stripe Standard API": re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            "GitHub Access Token": re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            "Slack Token": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
            "RSA Private Key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----')
        }

    def validate_scope(self) -> dict:
        in_scope = True
        if self.scope_domain:
            in_scope = self.host == self.scope_domain or self.host.endswith(f'.{self.scope_domain}')
        return {
            'confirmed': self.confirm_scope,
            'scope_domain': self.scope_domain,
            'in_scope': in_scope,
            'message': 'Scope confirmation is required.' if not self.confirm_scope else 'Scope confirmed.'
        }

    async def _fetch(self, session, url, method="GET", timeout=10, extra_headers=None):
        headers = {'User-Agent': 'TWReconHunter/0.2 (Python Async)'}
        headers.update(self.custom_headers)
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with session.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.text(errors='ignore')
                return True, resp.status, dict(resp.headers), body
        except Exception as e:
            return False, 0, {}, str(e)

    async def enum_subdomains(self, session) -> list:
        domain = self.host.split(':')[0]
        subdomains = set([domain])

        async def fetch_crtsh():
            ok, status, _, body = await self._fetch(session, f'https://crt.sh/?q=%25.{domain}&output=json')
            if ok and status == 200:
                try:
                    for item in json.loads(body):
                        for part in item.get('name_value', '').splitlines():
                            if part.strip().endswith(domain):
                                subdomains.add(part.strip())
                except: pass

        async def fetch_ht():
            ok, status, _, body = await self._fetch(session, f'https://api.hackertarget.com/hostsearch/?q={domain}')
            if ok and status == 200 and "error" not in body.lower():
                for line in body.splitlines():
                    parts = line.split(',')
                    if parts and parts[0].endswith(domain):
                        subdomains.add(parts[0].strip())

        async def fetch_alienvault():
            ok, status, _, body = await self._fetch(session, f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns')
            if ok and status == 200:
                try:
                    for r in json.loads(body).get('passive_dns', []):
                        if r.get('hostname', '').endswith(domain):
                            subdomains.add(r['hostname'].strip())
                except: pass
                
        async def fetch_certspotter():
            ok, status, _, body = await self._fetch(session, f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names')
            if ok and status == 200:
                try:
                    for record in json.loads(body):
                        for name in record.get('dns_names', []):
                            if name.endswith(domain):
                                subdomains.add(name.strip())
                except: pass

        await asyncio.gather(fetch_crtsh(), fetch_ht(), fetch_alienvault(), fetch_certspotter())
        return list(subdomains)[:50]

    async def crawl_and_mine(self, session, url: str) -> tuple:
        endpoints, js_files, findings, seen = [], [], [], set()
        
        async def parse_page(page_url, body):
            parser = LinkParser()
            parser.feed(body)
            js_pattern = re.compile(r'[\'"](/api/[^\'"\s]+|/v[1-9]/[^\'"\s]+|/users/[^\'"\s]+|/[a-zA-Z0-9_.-]+\.json)[\'"]')
            for m in js_pattern.findall(body):
                add_endpoint(m)
            for link in parser.links:
                add_endpoint(link.strip())
            for form in parser.forms:
                add_endpoint(form['action'], method='POST', params=form['inputs'])

        def add_endpoint(target, method='GET', params=None):
            if not target or target.startswith(('mailto:', 'javascript:', '#')): return
            parsed = urlparse(target)
            if parsed.netloc and parsed.netloc != self.host: return
            resolved = urljoin(url, target)
            if resolved not in seen:
                seen.add(resolved)
                if resolved.endswith('.js'): js_files.append(resolved)
                endpoints.append({'url': resolved, 'method': method, 'parameters': params or []})

        ok, status, headers, body = await self._fetch(session, url)
        if not ok: return endpoints, js_files, findings

        # Passive Findings
        lower_body = body.lower()
        if 'exception' in lower_body or 'traceback' in lower_body:
            findings.append({'severity': 'low', 'title': 'Verbose error leak', 'details': 'Body exposes error details.'})
        for name, regex in self.secrets_regex.items():
            if regex.search(body):
                findings.append({'severity': 'high', 'title': f'Secret Leak: {name}', 'details': f'Found in HTML body.'})

        await parse_page(url, body)

        if self.deep:
            # Spidering (depth 2)
            pages_to_crawl = [ep['url'] for ep in endpoints if ep['url'].startswith('http') and not ep['url'].endswith(('.js', '.css', '.png'))][:10]
            for page in pages_to_crawl:
                if page == url: continue
                p_ok, p_status, _, p_body = await self._fetch(session, page)
                if p_ok and p_status == 200:
                    await parse_page(page, p_body)
            
            # JS Mining
            js_pattern_deep = re.compile(r'[\'"](/api/[^\'"\s]+|/v[1-9]/[^\'"\s]+|/admin/[^\'"\s]+)[\'"]')
            for js in js_files:
                j_ok, j_status, _, j_body = await self._fetch(session, js)
                if j_ok and j_status == 200:
                    for m in js_pattern_deep.findall(j_body):
                        add_endpoint(m)
                    for name, regex in self.secrets_regex.items():
                        if regex.search(j_body):
                            findings.append({'severity': 'high', 'title': f'Secret Leak in JS: {name}', 'details': f'Found in {js}'})
                            
            # Wayback Machine
            w_ok, w_status, _, w_body = await self._fetch(session, f'http://web.archive.org/cdx/search/cdx?url=*.{self.host}/*&output=json&fl=original&collapse=urlkey&limit=50')
            if w_ok and w_status == 200:
                try:
                    for i, row in enumerate(json.loads(w_body)):
                        if i > 0 and row: add_endpoint(row[0])
                except: pass

        return endpoints, js_files, findings

    async def active_scan(self, session, endpoints, subdomains):
        findings = []
        
        # CORS Check
        ok, status, headers, _ = await self._fetch(session, self.base_url, method="OPTIONS", extra_headers={'Origin': 'https://evil.com'})
        if ok and headers.get('access-control-allow-origin') == 'https://evil.com':
            findings.append({'severity': 'medium', 'title': 'CORS Misconfiguration', 'details': 'Arbitrary origin reflected.'})

        # Directory Fuzzing
        targets = {'/.env': '=', '/.git/config': '[core]', '/server-status': 'Apache Status', '/swagger.json': 'swagger'}
        for path, sig in targets.items():
            ok, status, _, body = await self._fetch(session, self.base_url + path)
            if ok and status == 200 and (sig == '' or sig in body):
                findings.append({'severity': 'high', 'title': 'Sensitive File Exposed', 'details': f'Found at {path}'})

        # Subdomain Takeover
        signatures = {"AWS S3": "The specified bucket does not exist", "GitHub Pages": "There isn't a GitHub Pages site here.", "Heroku": "No such app"}
        for sub in subdomains:
            s_url = f"https://{sub}" if not sub.startswith("http") else sub
            ok, status, _, body = await self._fetch(session, s_url)
            if ok and status == 404:
                for provider, sig in signatures.items():
                    if sig in body:
                        findings.append({'severity': 'high', 'title': f'Subdomain Takeover: {provider}', 'details': f'Vulnerable at {s_url}'})

        # Param Fuzzing
        high_value = [ep['url'] for ep in endpoints if any(x in ep['url'].lower() for x in ['/api', '/admin', '/user'])]
        common_params = ['debug', 'admin', 'id']
        for url in high_value[:5]: # limit to save time
            b_ok, b_status, _, b_body = await self._fetch(session, url)
            if not b_ok: continue
            b_len = len(b_body)
            for p in common_params:
                fuzz_url = f"{url}?{p}=1" if '?' not in url else f"{url}&{p}=1"
                f_ok, f_status, _, f_body = await self._fetch(session, fuzz_url)
                if f_ok and (f_status != b_status or abs(len(f_body) - b_len) > 100):
                    findings.append({'severity': 'medium', 'title': 'Hidden Parameter Found', 'details': f'Parameter {p} changed response on {url}'})
                    
        return findings

    async def send_webhooks(self, session, findings):
        high_findings = [f"[{f['severity'].upper()}] {f['title']} - {f['details']}" for f in findings if f['severity'] in ['high', 'critical']]
        if not high_findings: return
        msg = f"TWReconHunter found {len(high_findings)} high severity issues on {self.target}\n" + "\n".join(high_findings)
        
        if self.discord:
            await session.post(self.discord, json={"content": msg})
        if self.telegram and ':' in self.telegram:
            token, chat_id = self.telegram.split(':', 1)
            await session.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": chat_id, "text": msg})

    async def run(self):
        async with aiohttp.ClientSession() as session:
            scope = self.validate_scope()
            subdomains = await self.enum_subdomains(session)
            endpoints, js_files, findings = await self.crawl_and_mine(session, self.base_url + '/')
            
            if self.active:
                active_findings = await self.active_scan(session, endpoints, subdomains)
                findings.extend(active_findings)
            
            report = {
                'target': self.target,
                'scope': scope,
                'subdomains': subdomains,
                'endpoints': endpoints,
                'findings': findings
            }
            
            await self.send_webhooks(session, findings)
            return report

def main():
    parser = argparse.ArgumentParser(description='TWReconHunter - Async Python Edition')
    parser.add_argument('-u', '--target', required=True, help='Target URL')
    parser.add_argument('--confirm-scope', action='store_true', help='Confirm scope')
    parser.add_argument('--deep', action='store_true', help='Deep JS Mining and Spidering')
    parser.add_argument('--active', action='store_true', help='Active checks (CORS, Fuzzing, Takeover)')
    parser.add_argument('--discord', help='Discord Webhook URL')
    parser.add_argument('--telegram', help='Telegram Token:ChatID')
    args = parser.parse_args()

    if not args.confirm_scope:
        print("Error: --confirm-scope required.")
        sys.exit(1)

    hunter = TWReconHunterAsync(args.target, confirm_scope=True, deep=args.deep, active=args.active, discord=args.discord, telegram=args.telegram)
    report = asyncio.run(hunter.run())
    
    print(json.dumps(report, indent=2))
    
if __name__ == '__main__':
    main()
