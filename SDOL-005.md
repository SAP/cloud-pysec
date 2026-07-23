# SDOL-005: OSS and 3rd Party Update and Maintenance Strategy

This document is the Update and Maintenance Strategy for **sap-xssec** (the SAP
Python Security Library, package `sap-xssec`), as required by the SAP product
standard **SDOL-005**.

`sap-xssec` is an SAP-provided open-source component that is consumed by other
SAP products. Per SDOL-005, SAP-provided open-source components are treated as
open-source components by their consumers. This document therefore also serves
as the citable maintenance statement that downstream SAP products may reference
in their own SDOL-005 evidence (see "Statement for downstream consumers" below).

- Accountable (strategy owner): sap-xssec Product Owner
- Last review: 2026-07-23
- Review cadence: at least once per release, and at least once every 12 months

## Update strategy

- Direct runtime dependencies should resolve to a version released within the
  last 12 months, tracking each upstream project's release cadence.
- Components must not be end-of-life or abandoned. Lifecycle status is reviewed
  using repository signals (archived status, release recency, commit/issue
  activity) at each review.
- Transitive dependencies are refreshed implicitly by keeping direct
  dependency floors current; they are reviewed on a risk basis.
- Development/test dependencies are kept reasonably current but are not shipped
  in the distributed artifact.
- Pre-release versions (alpha/beta/release candidate/dev) are not integrated
  into releases.

## Direct runtime dependencies

Declared in `setup.py`.

| Component | Constraint | Latest release | Released | Status |
| --- | --- | --- | --- | --- |
| cryptography | `>=49.0.0` | 49.0.0 | 2026-06-12 | Current |
| cachetools | `>=6.2.6` | 7.1.5 | 2026-07-22 | Current |
| urllib3 | `>=2.7.0` | 2.7.0 | 2026-05-07 | Current |
| pyjwt | `>=2.13.0` | 2.13.0 | 2026-05-21 | Current |
| httpx | `>=0.28.1` | 0.28.1 | 2024-12-06 | Risk-assessed (see below) |

`cachetools` is floored at `>=6.2.6` (released 2026-01-27, still within 12 months)
rather than the newest `7.x` line, because `cachetools>=7.0.0` requires Python
`>=3.10` while this library still supports Python 3.9. On Python 3.10+, pip will
resolve to the current `7.x` release.


Removed components:

- **six** — removed; it was unused in the shipped code.
- **deprecation** — removed; the upstream project is effectively abandoned
  (last release 2020-04-20). Its single use (a `@deprecated` decorator) was
  replaced with a small in-repo decorator in
  `sap/xssec/security_context_xsuaa.py`.

## Risk assessment: httpx

**Finding:** the latest stable `httpx` release (0.28.1, 2024-12-06) is older
than 12 months. This is an age finding, not a known vulnerability.

**Assessment:**

- httpx is actively maintained and is **not** end-of-life or abandoned. The
  repository (`encode/httpx`) is not archived, has ongoing commit and issue
  activity, and a 1.0 line is in active development (`1.0.devN` pre-releases).
- No known CVE affects the pinned version at the time of this review.
- The age solely reflects the maintainer's slow stable-release cadence; the
  maintained branch is current.

**Why not replaced:** httpx provides capabilities that are core to this library
and have no maintained drop-in equivalent that would yield a net security
benefit:

- asynchronous HTTP client (`httpx.AsyncClient`) used for async token retrieval,
- mutual-TLS client-certificate support (`httpx.Client(cert=...)`),
- the httpx exception hierarchy used in error handling.

Replacing a maintained, secure component purely to reset the release-age clock
would add churn and risk without improving security posture, which SDOL-005
explicitly does not require ("SDOL-005 does not seek to force teams onto the
highest possible version number").

**Mitigation plan:**

- Adopt httpx 1.0 once it reaches a stable (non-pre-release) version.
- Re-evaluate the maintenance/CVE status of httpx at each review (see cadence).
- If httpx becomes abandoned or a relevant CVE is disclosed without a timely
  fix, migrate to a maintained alternative following SDOL-014 SLAs.

## Statement for downstream consumers

`httpx` enters downstream SAP products as a transitive dependency of
`sap-xssec`. Version selection and maintenance decisions for `httpx` within
`sap-xssec` are owned by the `sap-xssec` team. Downstream products may reference
this document as the maintenance commitment for `httpx` in their own SDOL-005
strategy, on the understanding that this assessment is re-reviewed per the
cadence above and that this document reflects the current, maintained state.
