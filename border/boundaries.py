"""ROOT POLICY — OWNER REVIEW REQUIRED FOR EVERY CHANGE.

This registry decides which crossings may become independent evidence roots.
Changing it changes the Gate's security boundary. Conservative defaults:
real test runs, scans, and external API returns may be proposed as roots;
cached responses and retries are echoes unless a reviewed policy says otherwise.
"""

ROOT_POLICY: dict[str, bool] = {
    "test_run": False,
    "security_scan": False,
    "external_api_return": False,
}
