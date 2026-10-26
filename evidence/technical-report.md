# Technical report — GHSA-jpc4-w9r8-43j3

Researcher: Fernando Viana ([capivara-research](https://github.com/capivara-research))  
Vendor-coordinated advisory: GHSA-jpc4-w9r8-43j3  
Public advisory and safe PoC: https://github.com/capivara-research/GHSA-jpc4-w9r8-43j3

## Summary

Statamic's authenticated Control Panel endpoint POST /cp/fieldtypes/files/upload does not enforce the target asset container's upload permission. The same endpoint builds its extension allowlist from a base64-encoded field configuration supplied by the caller. An authenticated Control Panel user holding only the access cp permission can therefore bypass the upload {container} assets permission, the container validation rules, and the built-in file-extension allowlist to create a staged file with an arbitrary extension.

## Affected versions

The complete authorization-plus-extension-override chain is confirmed in Statamic 5.35.0 through 6.28.0. Missing authorization is present from at least 5.0.0 through 6.28.0; the caller-controlled allowed_extensions behavior was introduced after 5.30.0 and is present by 5.35.0. The report was reproduced end to end on a clean Statamic 6.28.0 installation.

## Security boundary and reproduction

The attacker is an authenticated, non-superuser Control Panel account with only access cp. The account does not have upload assets assets permission.

Using the same authenticated session:

1. POST /cp/assets correctly returns HTTP 403 with "This action is unauthorized."
2. POST /cp/fieldtypes/files/upload with container=assets, a harmless marker file, and a base64 field configuration decoding to {"type":"files","allowed_extensions":["proof"]} returns HTTP 200 and creates the staged .proof file.

The underlying controller does not call authorize(). It accepts the container identifier from the request and passes the uploaded file to Uploader::container(...). The caller-provided field configuration is merged into the fieldtype configuration and its allowed_extensions value is passed to AllowedFile as a complete replacement for the server's default safe list, rather than as a restriction of that list.

## Verified impact

The demonstrated impact is unauthorized server-side file creation and bypass of the product's extension and container validation controls. PHP, PHTML, HTACCESS and other arbitrary extensions were accepted during controlled testing. No remote code execution is claimed: on the default installation tested, staged files were written below storage/app/private/statamic/file-uploads and were not directly web-accessible. Deployment-specific storage exposure or later promotion of staged files could increase impact, but is not required for the reported authorization and policy bypass.

## Vendor coordination

The vulnerability was privately reported to Statamic through GitHub Private Vulnerability Reporting on 2026-08-24. Statamic maintainer jasonvarga accepted the report on 2026-10-06. GitHub records capivara-research as the reporter. The public repository includes screenshots of the GHSA, reporter credit, and maintainer acceptance.

## Duplicate analysis

No CVE is attached to GHSA-jpc4-w9r8-43j3, and exact searches of CVE.org, NVD, GitHub Advisory Database and VulDB found no record for this endpoint and root cause.

The closest record, CVE-2026-71434 / GHSA-qhr7-v3xp-vw9m, is distinct. It concerns unauthenticated public frontend forms failing to enforce administrator-configured upload restrictions. Statamic's global allowlist still blocked executable extensions in that issue, and it was fixed in 5.74.3 and 6.24.2. This report concerns an authenticated Control Panel endpoint, bypass of the upload-container authorization policy, and replacement of the global extension allowlist with caller-supplied values. It remains reproducible in 6.28.0, after the CVE-2026-71434 fix.

CVE-2026-49288 is also distinct: it concerns unauthorized read-only disclosure from Control Panel fieldtype endpoints and explicitly states that no data can be modified. This report demonstrates unauthorized file creation.

CWE-862: Missing Authorization
CWE-434: Unrestricted Upload of File with Dangerous Type
Suggested CVSS 3.1: 5.4 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L)

## Recommended remediation

Resolve and validate the requested asset container server-side; enforce the same store authorization policy used by AssetsController; apply the container's validation rules; and ensure caller-supplied allowed_extensions can only narrow, never replace or expand, the server-side safe extension list.
