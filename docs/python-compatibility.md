# Python compatibility review

v0.3.0 supports Python 3.10 and later. The gateway agent and privileged helper remain Linux-specific. CI tests 3.10, 3.11, 3.12 and 3.13, builds distributions, and checks the wheel's Requires-Python field.

The compatibility review found no Python 3.11-only syntax or standard-library APIs in application code. The certificate tests used datetime.UTC, introduced in 3.11; they now use the equivalent datetime.timezone.utc. Ruff explicitly targets py310 so future suggestions retain this compatibility.

A Python 3.11/OpenSSL build reported TLS client-certificate rejection as httpx.ReadError (broken pipe) instead of RemoteProtocolError. The negative tests now recognize specific connection/protocol failure variants, exclude timeouts, and require a successful authorized mTLS health request after every rejection. Missing, untrusted and expired client certificates must still fail before an HTTP response, while a trusted but unauthorized identity must still receive 403. No application security checks were relaxed.

## Dependencies

Fresh installations resolved these versions. Each installed runtime, transitive, test and build-tool distribution's Requires-Python metadata was checked against its actual interpreter. Both complete suites passed 77 tests with no skips on CPython 3.10.12 and 3.11.16. The only warning was the upstream Starlette/httpx TestClient deprecation.

| Required dependency | Tested version on both interpreters | Requires-Python |
| --- | --- | --- |
| FastAPI | 0.162.0 | >=3.10 |
| Uvicorn | 0.54.0 | >=3.10 |
| Pydantic | 2.14.2 | >=3.10 |
| PyYAML | 6.0.3 | >=3.8 |
| prometheus-client | 0.26.0 | >=3.9 |
| HTTPX | 0.28.1 | >=3.8 |
| cryptography | 46.0.7 | >=3.8, excluding 3.9.0 and 3.9.1 |

The resolver chose Starlette 1.7.0 and pycparser 3.11 on Python 3.10; Starlette 1.10.0 and pycparser 3.12 require Python 3.11. Those newer transitive versions cannot be forced into a 3.10 environment. Existing dependency ranges allow compatible resolution without additional pins. Python 3.10 also receives exceptiongroup and tomli backports as declared by dependencies. Test tools pytest 9.2.0 and Ruff 0.17.3, build 1.6.1, and isolated Hatchling 1.33.0 all installed and ran successfully on both interpreters. Future dependency resolution remains governed by package metadata and CI.

The compatibility work does not alter application transport, certificate verification, privileged-helper authorization, fixed command execution, or diagnostic evaluation. Run the full security suite when updating Python or dependencies, because OpenSSL versions can change the surfaced error type.
