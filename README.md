# DevSecOps Pipeline

An end-to-end **secure delivery pipeline** for a small REST API. Every push runs code-quality, security and infrastructure checks in parallel; the container image is built, smoke-tested, vulnerability-scanned and given an SBOM, and is published only when every gate passes.

The service itself (a multi-tenant notes API in Flask) is deliberately small; the point of the project is everything around it: the pipeline, the hardened container, and secure infrastructure as code.

## Pipeline

```
push / PR
   │
   ├── test          ruff lint · pytest · coverage gate (≥ 85%)
   ├── sast          Bandit static analysis
   ├── secrets       Gitleaks scan of full git history
   ├── dependencies  pip-audit against known CVEs
   └── iac           terraform fmt + validate · kubeconform schema check · Checkov
          │
          ▼  (all five must pass)
        build        docker build → container smoke test → Trivy image scan → SBOM (SPDX)
          │
          ▼  (main branch only)
        publish      push image to GitHub Container Registry, tagged with the commit SHA
```

Defined in [`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml). Checkov findings are uploaded to the repository's **Security** tab (SARIF) and reported without blocking; every other security stage blocks the build.

## Security built into the application

| Control | Where |
| --- | --- |
| API-key auth; keys stored only as SHA-256 hashes, constant-time comparison | `app/main.py` |
| Strict validation with pydantic: length limits, unknown fields rejected (blocks mass assignment) | `NoteIn` model |
| Parameterised SQL everywhere (SQL injection) | `app/db.py` |
| Tenant isolation: every query is scoped to the caller (IDOR) | `app/db.py` |
| Per-key rate limiting and a 16 KB request-body cap | `RateLimiter`, `MAX_CONTENT_LENGTH` |
| Security headers on every response: CSP, HSTS, nosniff, frame-deny, no-referrer, no-store | `SECURITY_HEADERS` |
| Generic error messages with a request ID, never stack traces; structured JSON logs | error handlers |
| Health, readiness and metrics endpoints | `/healthz`, `/readyz`, `/metrics` |

Each control has a test in `tests/test_app.py`, including tenant isolation, a mass-assignment attempt, an SQL-injection payload, oversized bodies and rate limiting.

## Hardened container

Multi-stage build, slim base, dependencies in a virtualenv, runs as an unprivileged user (UID 10001), no build tools in the final image, built-in health check.

## Infrastructure as code

**Terraform (AWS)** — `terraform/`
- ECR registry with **immutable tags**, scan-on-push and KMS encryption, plus a lifecycle policy
- Private S3 bucket for audit logs: public access blocked, versioning, SSE-KMS, TLS-only bucket policy, archive-then-expire lifecycle
- Customer-managed KMS key with automatic rotation

**Kubernetes** — `k8s/`
- Namespace enforcing the **restricted Pod Security Standard**
- Deployment: non-root, read-only root filesystem, all Linux capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, no service-account token, resource limits, liveness and readiness probes
- **Default-deny NetworkPolicy** with a single allow rule from the ingress controller
- API keys supplied from a Secret (example only, never committed)

## Run locally

```bash
pip install -r requirements-dev.txt
pytest -q --cov=app

# generate a key hash and start the API
export API_KEY_HASHES="alice:$(python -c "import hashlib;print(hashlib.sha256(b'dev-key').hexdigest())")"
flask --app "app.main:create_app()" run --port 8000

curl -H "X-API-Key: dev-key" -H "Content-Type: application/json" \
     -d '{"title":"hello","body":"first note"}' localhost:8000/api/v1/notes
curl -H "X-API-Key: dev-key" localhost:8000/api/v1/notes
curl -i localhost:8000/api/v1/notes          # 401, with security headers
```

With Docker:

```bash
docker build -t secure-notes .
docker run -p 8000:8000 -e API_KEY_HASHES="$API_KEY_HASHES" secure-notes
```

## Project layout

```
app/                 Flask API and SQLite store
tests/               functional and security tests
Dockerfile           multi-stage, non-root image
terraform/           AWS registry, KMS and log bucket
k8s/                 namespace, deployment, service, network policies, secret example
.github/workflows/   the DevSecOps pipeline
```

## Limitations and next steps

- SQLite on an `emptyDir` volume is for demonstration; production would use a managed database.
- Next: sign images with Cosign and verify signatures at admission, add DAST (OWASP ZAP) against a preview deployment, and deploy through GitOps (Argo CD).
