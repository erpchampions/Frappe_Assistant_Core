"""
OAuth callback endpoint — receives the authorization code after user approves.
The bridge polls this endpoint to get the code instead of requiring a local
HTTP server (which doesn't work in remote/container setups).
"""

import frappe

# In-memory store for auth codes (keyed by state parameter)
# Uses Frappe's cache which is shared across requests
CACHE_KEY_PREFIX = "fac_oauth_callback"


@frappe.whitelist(allow_guest=True)
def callback(**kwargs):
    """
    Receives the OAuth redirect with the authorization code.

    The bridge registers with redirect_uri pointing here instead of localhost.
    After the user approves, Frappe redirects to this endpoint, which stores
    the code. The bridge polls until it gets the code.

    URL: /api/method/frappe_assistant_core.api.oauth_callback.callback
    """
    code = frappe.form_dict.get("code")
    state = frappe.form_dict.get("state")
    error = frappe.form_dict.get("error")

    if error:
        frappe.cache.set_value(f"{CACHE_KEY_PREFIX}:{state}:error", error, expires_in_sec=300)
        _respond_html(_html_page("Authorization Denied",
                       "The authorization was denied or failed.",
                       "You may close this tab."))
        return

    if code and state:
        frappe.cache.set_value(f"{CACHE_KEY_PREFIX}:{state}:code", code, expires_in_sec=300)
        _respond_html(_html_page("Authorized ✓",
                       "The bridge has received your authorization.",
                       "You may close this tab and return to the terminal."))
        return

    _respond_html(_html_page("Waiting", "No authorization code received.", ""))
    return


@frappe.whitelist(allow_guest=True)
def get_code(state: str = None):
    """
    Poll for the authorization code. Returns JSON with 'code' or 'error'.
    Called by the bridge while waiting for the user to authorize.

    URL: /api/method/frappe_assistant_core.api.oauth_callback.get_code?state=XXX
    """
    state = state or frappe.form_dict.get("state", "")
    if not state:
        return {"error": "Missing state parameter"}

    code_key = f"{CACHE_KEY_PREFIX}:{state}:code"
    error_key = f"{CACHE_KEY_PREFIX}:{state}:error"

    error = frappe.cache.get_value(error_key)
    if error:
        frappe.cache.delete_value(error_key)
        frappe.cache.delete_value(code_key)
        return {"error": error}

    code = frappe.cache.get_value(code_key)
    if code:
        frappe.cache.delete_value(code_key)
        return {"code": code}

    return {"code": None}


def _poll_for_code(state: str, timeout: int = 120) -> str | None:
    """Poll for an authorization code. Returns code or None if timeout."""
    import time
    deadline = time.time() + timeout
    code_key = f"{CACHE_KEY_PREFIX}:{state}:code"
    error_key = f"{CACHE_KEY_PREFIX}:{state}:error"

    while time.time() < deadline:
        error = frappe.cache.get_value(error_key)
        if error:
            frappe.cache.delete_value(error_key)
            frappe.cache.delete_value(code_key)
            raise Exception(f"Authorization failed: {error}")

        code = frappe.cache.get_value(code_key)
        if code:
            frappe.cache.delete_value(code_key)
            return code

        time.sleep(0.5)

    return None


def _respond_html(html: str) -> None:
    """Return raw HTML response (bypasses Frappe JSON wrapping)."""
    from werkzeug.exceptions import HTTPException
    from werkzeug.wrappers import Response

    class _HTMLResponse(HTTPException):
        code = 200
        def __init__(self, r):
            self.r = r
        def get_response(self, environ=None):
            return self.r

    raise _HTMLResponse(Response(html, content_type="text/html; charset=utf-8"))


def _html_page(title: str, message: str, extra: str) -> str:
    """Minimal HTML response page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f4f5f7}}
.card{{background:#fff;border-radius:10px;padding:36px 32px;max-width:400px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
h2{{font-size:20px;color:#111827;margin-bottom:8px}}
p{{color:#6b7280;font-size:14px;margin:0}}
</style></head>
<body><div class="card"><h2>{title}</h2><p>{message}</p>{f'<p style="margin-top:8px;font-size:13px">{extra}</p>' if extra else ''}</div></body></html>"""
