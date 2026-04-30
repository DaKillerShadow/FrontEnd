# =============================================================================
# modules/deep_analyzer.py  —  DeepAnalyzer (Dynamic / Runtime Analysis)
# =============================================================================
# PURPOSE:
#   This module implements the DEEP PATH — triggered only when the Fast Path
#   (static rule + ML analysis) returns "suspicious" or "likely_phishing".
#
#   It performs DYNAMIC analysis by actually navigating to the URL in a
#   headless browser instance and inspecting the rendered page. This is far
#   more powerful than lexical analysis but also far slower (~5-30 seconds).
#
# CAPABILITIES:
#   1. Redirect Tracing    – Follow every 3xx HTTP redirect recursively to
#                            uncover the final destination of shortened links
#                            and redirect chains.
#   2. Screenshot Capture  – Take a full-page screenshot for human review.
#   3. DOM Analysis        – Inspect rendered HTML for phishing indicators:
#                            login forms, password fields, hidden iframes.
#   4. BiTB Detection      – Detect Browser-in-the-Browser attacks by checking
#                            for iframe elements with coordinates that overlap
#                            the viewport top bar (simulated browser UI).
#   5. Domain Age (WHOIS)  – Query WHOIS data to flag newly registered domains
#                            (< 30 days old) — a strong phishing indicator.
#
# DEPENDENCIES:
#   pip install selenium webdriver-manager requests python-whois
#   Chrome or Firefox must be installed on the server.
# =============================================================================

import logging
import time
import base64
import re
import json
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Optional heavy dependencies (graceful degradation if not installed) ────────
try:
    import whois as python_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False
    logger.warning('python-whois not installed; domain-age checks disabled.')

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import WebDriverException, TimeoutException
    from webdriver_manager.chrome import ChromeDriverManager
    _SELENIUM_AVAILABLE = True
except ImportError:
    _SELENIUM_AVAILABLE = False
    logger.warning('selenium/webdriver-manager not installed; headless browser disabled.')


# ── Constants ─────────────────────────────────────────────────────────────────
MAX_REDIRECTS      = 10          # maximum hops to follow
REQUEST_TIMEOUT    = 10          # seconds per HTTP request
BROWSER_TIMEOUT    = 20          # seconds for page load
NEW_DOMAIN_DAYS    = 30          # domains younger than this are high-risk
BITB_OVERLAP_PX    = 80          # iframe top-edge within this many px of page top

# BiTB heuristic: keywords typically present in fake browser UI iframes
BITB_KEYWORDS = [
    'google.com/accounts', 'microsoft.com/login', 'apple.com/sign',
    'facebook.com/login', 'accounts.google', 'login.live.com',
]


class DeepAnalyzer:
    """
    Performs dynamic, runtime analysis of a URL using a headless browser
    and HTTP redirect tracing.
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, url: str) -> dict:
        """
        Run the full deep-path analysis suite.

        Parameters
        ----------
        url : str   The URL to analyse (already validated by URLValidator).

        Returns
        -------
        dict — comprehensive dynamic analysis report.
        """
        result = {
            'url':            url,
            'redirect_chain': [],
            'final_url':      url,
            'domain_age':     None,
            'domain_age_days': None,
            'newly_registered': False,
            'has_login_form':  False,
            'has_password_field': False,
            'hidden_iframes':  0,
            'bitb_detected':   False,
            'bitb_detail':     '',
            'screenshot_b64':  None,
            'dom_signals':     [],
            'deep_risk_score': 0,
            'deep_flags':      [],
            'selenium_available': _SELENIUM_AVAILABLE,
            'whois_available':    _WHOIS_AVAILABLE,
            'error':           '',
        }

        # ── Step 1: Trace redirect chain ──────────────────────────────────────
        try:
            redirect_result = self._trace_redirects(url)
            result['redirect_chain'] = redirect_result['chain']
            result['final_url']      = redirect_result['final_url']

            if redirect_result['changed_domain']:
                result['deep_flags'].append({
                    'flag':     'domain_changed_after_redirect',
                    'severity': 'high',
                    'detail':   (
                        f"URL redirected to a different domain. "
                        f"Original: {urlparse(url).netloc} → "
                        f"Final: {urlparse(redirect_result['final_url']).netloc}"
                    ),
                })
                result['deep_risk_score'] += 3

            if len(redirect_result['chain']) > 3:
                result['deep_flags'].append({
                    'flag':     'excessive_redirects',
                    'severity': 'medium',
                    'detail':   f"{len(redirect_result['chain'])} redirects detected. "
                                "Long redirect chains are used to obscure final destinations.",
                })
                result['deep_risk_score'] += 1

        except Exception as exc:
            logger.warning('Redirect tracing failed: %s', exc)
            result['error'] += f'redirect_trace_error: {exc}; '

        # ── Step 2: WHOIS domain age check ────────────────────────────────────
        try:
            final_domain = urlparse(result['final_url']).netloc.split(':')[0]
            age_result   = self._check_domain_age(final_domain)
            result['domain_age']      = age_result['registration_date']
            result['domain_age_days'] = age_result['age_days']
            result['newly_registered'] = age_result['newly_registered']

            if age_result['newly_registered']:
                result['deep_flags'].append({
                    'flag':     'newly_registered_domain',
                    'severity': 'high',
                    'detail':   (
                        f"Domain '{final_domain}' was registered "
                        f"{age_result['age_days']} days ago (< {NEW_DOMAIN_DAYS} days). "
                        "Newly registered domains are a strong phishing indicator."
                    ),
                })
                result['deep_risk_score'] += 4

        except Exception as exc:
            logger.warning('WHOIS check failed: %s', exc)
            result['error'] += f'whois_error: {exc}; '

        # ── Step 3: Headless browser analysis ─────────────────────────────────
        if _SELENIUM_AVAILABLE:
            try:
                browser_result = self._browser_analyze(result['final_url'])
                result['has_login_form']      = browser_result['has_login_form']
                result['has_password_field']  = browser_result['has_password_field']
                result['hidden_iframes']      = browser_result['hidden_iframes']
                result['bitb_detected']       = browser_result['bitb_detected']
                result['bitb_detail']         = browser_result['bitb_detail']
                result['screenshot_b64']      = browser_result['screenshot_b64']
                result['dom_signals']         = browser_result['dom_signals']

                if browser_result['bitb_detected']:
                    result['deep_flags'].append({
                        'flag':     'bitb_attack',
                        'severity': 'high',
                        'detail':   browser_result['bitb_detail'],
                    })
                    result['deep_risk_score'] += 5

                if browser_result['has_password_field'] and browser_result['has_login_form']:
                    result['deep_flags'].append({
                        'flag':     'credential_harvesting_form',
                        'severity': 'high',
                        'detail':   'Page contains a login form with a password field. '
                                    'Credentials entered here may be stolen.',
                    })
                    result['deep_risk_score'] += 2

                if browser_result['hidden_iframes'] > 0:
                    result['deep_flags'].append({
                        'flag':     'hidden_iframes',
                        'severity': 'medium',
                        'detail':   f"{browser_result['hidden_iframes']} hidden/zero-size "
                                    "iframes detected. These are used to load malicious "
                                    "content invisibly.",
                    })
                    result['deep_risk_score'] += 1

            except Exception as exc:
                logger.warning('Browser analysis failed: %s', exc)
                result['error'] += f'browser_error: {exc}; '
        else:
            result['error'] += 'selenium_not_installed; '

        return result

    # ── Private: Redirect Tracing ──────────────────────────────────────────────

    def _trace_redirects(self, url: str) -> dict:
        """
        Follow HTTP redirects (3xx) recursively up to MAX_REDIRECTS hops.
        Uses requests with allow_redirects=False to inspect each hop.
        """
        chain      = []
        current    = url
        original_netloc = urlparse(url).netloc.lower()

        session = requests.Session()
        session.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )

        for hop in range(MAX_REDIRECTS):
            try:
                resp = session.get(
                    current,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                )
                chain.append({
                    'hop':         hop + 1,
                    'url':         current,
                    'status_code': resp.status_code,
                })

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if not location:
                        break
                    # Handle relative redirects
                    if location.startswith('/'):
                        parsed = urlparse(current)
                        location = f'{parsed.scheme}://{parsed.netloc}{location}'
                    current = location
                else:
                    break   # Not a redirect; we've reached the final destination

            except requests.exceptions.SSLError:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': 'ssl_error'})
                break
            except requests.exceptions.ConnectionError:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': 'connection_error'})
                break
            except Exception as exc:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': f'error: {exc}'})
                break

        final_netloc   = urlparse(current).netloc.lower()
        changed_domain = (final_netloc != original_netloc and bool(final_netloc))

        return {
            'chain':          chain,
            'final_url':      current,
            'changed_domain': changed_domain,
        }

    # ── Private: Domain Age (WHOIS) ───────────────────────────────────────────

    def _check_domain_age(self, domain: str) -> dict:
        """
        Query WHOIS data for *domain* and calculate its age in days.
        Falls back gracefully if python-whois is not installed.
        """
        base_result = {
            'registration_date': None,
            'age_days':          None,
            'newly_registered':  False,
        }

        if not _WHOIS_AVAILABLE:
            return base_result

        try:
            w = python_whois.whois(domain)
            creation_date = w.creation_date

            # creation_date can be a list or a single datetime
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                return base_result

            # Ensure timezone-aware datetime for comparison
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_days = (now - creation_date).days
            return {
                'registration_date': creation_date.isoformat(),
                'age_days':          age_days,
                'newly_registered':  age_days < NEW_DOMAIN_DAYS,
            }

        except Exception as exc:
            logger.debug('WHOIS query failed for %s: %s', domain, exc)
            return base_result

    # ── Private: Headless Browser Analysis ────────────────────────────────────

    def _browser_analyze(self, url: str) -> dict:
        """
        Launch a headless Chrome instance, navigate to *url*, and inspect
        the rendered DOM for phishing indicators.
        """
        result = {
            'has_login_form':     False,
            'has_password_field': False,
            'hidden_iframes':     0,
            'bitb_detected':      False,
            'bitb_detail':        '',
            'screenshot_b64':     None,
            'dom_signals':        [],
        }

        options = ChromeOptions()
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1280,800')
        options.add_argument('--disable-extensions')
        options.add_argument('--ignore-certificate-errors')
        # Use a realistic User-Agent to avoid bot-detection blocks
        options.add_argument(
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )

        driver = None
        try:
            service = ChromeService(ChromeDriverManager().install())
            driver  = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(BROWSER_TIMEOUT)

            driver.get(url)
            time.sleep(2)   # allow JS to render

            # ── Take screenshot ────────────────────────────────────────────
            screenshot_bytes     = driver.get_screenshot_as_png()
            result['screenshot_b64'] = base64.b64encode(screenshot_bytes).decode()

            # ── Check for login forms ──────────────────────────────────────
            password_fields = driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
            login_forms     = driver.find_elements(
                By.XPATH,
                '//form[.//input[@type="password"] or .//input[@type="text"]]'
            )
            result['has_password_field'] = len(password_fields) > 0
            result['has_login_form']     = len(login_forms) > 0

            if result['has_login_form']:
                result['dom_signals'].append('login_form_present')

            # ── Scan iframes for BiTB attack ───────────────────────────────
            iframes = driver.find_elements(By.TAG_NAME, 'iframe')
            hidden_count   = 0
            bitb_detected  = False
            bitb_detail    = ''

            viewport_height = driver.execute_script('return window.innerHeight')

            for iframe in iframes:
                location = iframe.location
                size     = iframe.size
                src      = iframe.get_attribute('src') or ''
                style    = iframe.get_attribute('style') or ''

                # Hidden iframes: zero size or display:none
                if size['width'] == 0 or size['height'] == 0:
                    hidden_count += 1
                    continue
                if 'display:none' in style.replace(' ', '') or \
                   'visibility:hidden' in style.replace(' ', ''):
                    hidden_count += 1
                    continue

                # BiTB check: iframe positioned to mimic a browser window
                # Phishing kit places a large iframe near the top of the page
                # with coordinates that overlap the "browser chrome" area.
                top_y  = location.get('y', 9999)
                width  = size.get('width', 0)
                height = size.get('height', 0)

                is_large    = width > 400 and height > 300
                is_near_top = top_y < BITB_OVERLAP_PX

                # Check if src contains known authentication domain keywords
                src_suspicious = any(kw in src for kw in BITB_KEYWORDS)

                if is_large and (is_near_top or src_suspicious):
                    bitb_detected = True
                    bitb_detail = (
                        f"Iframe at y={top_y}px (size {width}×{height}) "
                        f"appears to simulate a browser window "
                        f"{'containing a known auth URL' if src_suspicious else 'near page top'}. "
                        "This is a Browser-in-the-Browser (BiTB) attack pattern."
                    )
                    result['dom_signals'].append('bitb_iframe_detected')

            result['hidden_iframes'] = hidden_count
            result['bitb_detected']  = bitb_detected
            result['bitb_detail']    = bitb_detail

            # ── Other DOM signals ──────────────────────────────────────────
            # Check for urgency language in visible text
            body_text = driver.find_element(By.TAG_NAME, 'body').text.lower()
            urgency_words = [
                'verify your account', 'confirm your identity', 'suspended',
                'unusual activity', 'click here immediately', 'expires in',
                'your account has been', 'limited access',
            ]
            for phrase in urgency_words:
                if phrase in body_text:
                    result['dom_signals'].append(f'urgency_language: "{phrase}"')

        except TimeoutException:
            result['dom_signals'].append('page_load_timeout')
        except WebDriverException as exc:
            raise RuntimeError(f'WebDriver error: {exc}') from exc
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return result
