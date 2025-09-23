# app/core/header_analyzer_engine.py
import httpx
from PySide6.QtCore import QObject, Signal

class HeaderAnalyzerEngine(QObject):
    """A specialized engine to fetch and analyze HTTP security headers."""
    
    # Emits a dictionary of found headers
    scan_complete = Signal(dict)
    # Emits an error string
    scan_error = Signal(str)

    def __init__(self, task_manager):
        super().__init__()
        self.task_manager = task_manager

    def start_analysis(self, url: str):
        self.task_manager.create_task(self._run_analysis(url))

    async def _run_analysis(self, url: str):
        """Fetches headers and analyzes them."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                response = await client.get(url, timeout=15)
                
            analysis = self._analyze_headers(response.headers)
            self.scan_complete.emit(analysis)
            
        except httpx.RequestError as e:
            self.scan_error.emit(f"Could not connect to target: {e}")
        except Exception as e:
            self.scan_error.emit(f"An unexpected error occurred: {e}")

    def _analyze_headers(self, headers: httpx.Headers) -> dict:
        """Checks for the presence and configuration of key security headers."""
        results = {}
        
        # 1. Strict-Transport-Security (HSTS)
        hsts = headers.get('strict-transport-security')
        if hsts:
            results['Strict-Transport-Security'] = {
                "value": hsts,
                "present": True,
                "comment": "Good. Enforces HTTPS, protecting against downgrade attacks."
            }
        else:
            results['Strict-Transport-Security'] = {
                "value": "Not Present",
                "present": False,
                "comment": "Warning: HSTS header is missing. The site is vulnerable to SSL stripping attacks."
            }
            
        # 2. X-Frame-Options
        xfo = headers.get('x-frame-options')
        if xfo:
            results['X-Frame-Options'] = {
                "value": xfo,
                "present": True,
                "comment": "Good. Protects against clickjacking by controlling framing."
            }
        else:
            results['X-Frame-Options'] = {
                "value": "Not Present",
                "present": False,
                "comment": "Warning: X-Frame-Options header is missing, increasing clickjacking risk."
            }
            
        # 3. X-Content-Type-Options
        xcto = headers.get('x-content-type-options')
        if xcto and xcto.lower() == 'nosniff':
            results['X-Content-Type-Options'] = {
                "value": xcto,
                "present": True,
                "comment": "Good. 'nosniff' prevents browsers from MIME-sniffing the content type."
            }
        else:
            results['X-Content-Type-Options'] = {
                "value": xcto or "Not Present",
                "present": False,
                "comment": "Warning: X-Content-Type-Options header is missing or not 'nosniff'."
            }
            
        # 4. Content-Security-Policy (CSP)
        csp = headers.get('content-security-policy')
        if csp:
            results['Content-Security-Policy'] = {
                "value": csp,
                "present": True,
                "comment": "Good. CSP is present, providing a strong defense against XSS."
            }
        else:
            results['Content-Security-Policy'] = {
                "value": "Not Present",
                "present": False,
                "comment": "Warning: Content-Security-Policy header is missing. This is a key protection against XSS."
            }

        # 5. Permissions-Policy
        pp = headers.get('permissions-policy')
        if pp:
            results['Permissions-Policy'] = {
                "value": pp,
                "present": True,
                "comment": "Good. Permissions-Policy is present, restricting sensitive browser features."
            }
        else:
            results['Permissions-Policy'] = {
                "value": "Not Present",
                "present": False,
                "comment": "Info: Consider adding a Permissions-Policy header to enhance security."
            }
            
        return results
