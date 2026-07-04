"""
Lightweight OAuth Authorization Page — returns a 2KB page instead of 335KB.
"""

import frappe
from frappe.integrations.oauth2 import get_oauth_server
from frappe_assistant_core.utils.oauth_compat import get_oauth_settings
from oauthlib.oauth2 import FatalClientError, OAuth2Error
from werkzeug.wrappers import Response


@frappe.whitelist(allow_guest=True)
def authorize(**kwargs):
    """Lightweight OAuth authorization — serves minimal HTML directly."""

    # Build URLs (same logic as Frappe core)
    success_url = (
        "/api/method/frappe.integrations.oauth2.approve?"
        + frappe.integrations.oauth2.encode_params(
            frappe.integrations.oauth2.sanitize_kwargs(kwargs)
        )
    )
    failure_url = frappe.form_dict.get("redirect_uri", "") + "?error=access_denied"

    # Redirect to login if not authenticated
    if frappe.session.user == "Guest":
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = (
            "/login?"
            + frappe.integrations.oauth2.encode_params({"redirect-to": frappe.request.url})
        )
        return

    try:
        r = frappe.request
        scopes, frappe.flags.oauth_credentials = get_oauth_server().validate_authorization_request(
            r.url, r.method, r.get_data(), r.headers
        )

        # Auto-approve if configured
        skip_auth = frappe.db.get_value(
            "OAuth Client", frappe.flags.oauth_credentials["client_id"], "skip_authorization"
        )
        unrevoked_tokens = frappe.get_all("OAuth Bearer Token", filters={"status": "Active"})
        if skip_auth or (get_oauth_settings().get("skip_authorization") == "Auto" and unrevoked_tokens):
            frappe.local.response["type"] = "redirect"
            frappe.local.response["location"] = success_url
            return

        if "openid" in scopes:
            scopes.remove("openid")
            scopes.extend(["Full Name", "Email", "User Image", "Roles"])

        client_name = frappe.db.get_value("OAuth Client", kwargs["client_id"], "app_name") or "Unknown"
        details = "".join(f"<li>{s.title()}</li>" for s in scopes)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Access — {client_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f5f7;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#fff;border-radius:10px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:36px 32px;max-width:420px;width:90%}}
h2{{font-size:20px;color:#111827;margin:0 0 4px}}
.sub{{color:#6b7280;font-size:14px;margin-bottom:20px}}
ul{{list-style:none;margin-bottom:24px}}
li{{padding:9px 0;border-bottom:1px solid #f3f4f6;font-size:14px;color:#374151}}
li:last-child{{border-bottom:none}}
.btns{{display:flex;gap:12px}}
.btn{{flex:1;padding:11px 0;border-radius:7px;font-size:15px;font-weight:600;text-align:center;text-decoration:none;display:inline-block;transition:background .15s}}
.btn-deny{{background:#f3f4f6;color:#374151;border:1px solid #d1d5db}}
.btn-deny:hover{{background:#e5e7eb}}
.btn-allow{{background:#1a56db;color:#fff}}
.btn-allow:hover{{background:#1e40af}}
</style>
</head>
<body>
<div class="card">
<h2>{client_name}</h2>
<p class="sub">wants to access the following details from your account</p>
<ul>{details}</ul>
<div class="btns">
<a href="{failure_url}" class="btn btn-deny">Deny</a>
<a href="{success_url}" class="btn btn-allow">Allow</a>
</div>
</div>
</body>
</html>"""

        # Return raw HTML — bypass Frappe's 335KB page template via HTTPException
        from werkzeug.exceptions import HTTPException

        class _OAuthResponse(HTTPException):
            code = 200
            def __init__(self, resp):
                self.resp = resp
            def get_response(self, environ=None):
                return self.resp

        response = Response(html, content_type="text/html; charset=utf-8")
        raise _OAuthResponse(response)

    except (FatalClientError, OAuth2Error) as e:
        frappe.local.response["http_status_code"] = 400
        frappe.local.response["error"] = str(e)
        return
