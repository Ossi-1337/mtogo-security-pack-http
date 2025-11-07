# MToGo — Security Automation Pack (HTTP-friendly local)

This repo is a minimal .NET 8 Web API wired with **automatic security gates** for exams/demos:

- GitHub Actions: build+tests, **CodeQL**, **Trivy (fs + image)**, **Gitleaks** gate all merges.
- Containers: multi-stage **non-root** image.
- Kubernetes: Deployment with liveness/readiness, resource limits; HTTPS Ingress with HSTS (prod), and **HTTP-only dev Ingress**.
- API defenses: JWT auth, ownership policy (prevents IDOR), **rate limiting**, **strict JSON** (unknown fields → 400), security headers.
- Tests: 401/403, 429, strict JSON and headers.

---

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/)
- Docker (for image build + Trivy image scan)
- [Trivy](https://github.com/aquasecurity/trivy) and [Gitleaks](https://github.com/gitleaks/gitleaks) in PATH (optional for local demo)
- Make (optional) — or run the commands manually

---

## Run locally over HTTP (step-by-step)

1. **Restore & build**
   ```bash
   dotnet restore
   dotnet build -warnaserror -c Release
   ```

2. **Run the API (HTTP on 8080)**
   ```bash
   dotnet run --project src/MToGo.Api --urls http://localhost:8080
   ```

3. **Check health**
   ```bash
   curl.exe http://localhost:8080/health/live
   curl.exe http://localhost:8080/health/ready
   ```

4. **Try a protected endpoint (shows 401 without token)**
   ```bash
   curl.exe -i http://localhost:8080/api/users/u1/orders
   ```

5. **Try again *with* a demo token**
   - Token for `u1` (owner):  
     ```
     test.eyJzdWIiOiAidTEifQ.sig
     ```
   - Token for `u2` (non-owner):  
     ```
     test.eyJzdWIiOiAidTIifQ.sig
     ```

   Call **as owner** (200 OK expected):
   ```bash
   curl.exe -i -H "Authorization: Bearer test.eyJzdWIiOiAidTEifQ.sig" http://localhost:8080/api/users/u1/orders
   ```

   Call **as NOT owner** (403 expected):
   ```bash
   curl.exe -i -H "Authorization: Bearer test.eyJzdWIiOiAidTIifQ.sig" http://localhost:8080/api/users/u1/orders
   ```

6. **Strict JSON demo** (unknown field → 400)
   ```bash
   curl.exe -i -H "Authorization: Bearer test.eyJzdWIiOiAidTEifQ.sig" -H "Content-Type: application/json" \        -d '{"known":"x","unknownField":123}' http://localhost:8080/api/some-endpoint
   ```

7. **Rate limiting demo** (429 after burst)
   ```bash
   for i in $(seq 1 150); do curl -s -o /dev/null -w "%{http_code} " -H "Authorization: Bearer test.eyJzdWIiOiAidTEifQ.sig" http://localhost:8080/api/users/u1/orders; done
   echo
   ```

8. **Run tests**
   ```bash
   dotnet test -c Release
   ```

9. **Run local security scans (optional)**
   ```bash
   make gitleaks
   make scan-fs
   make scan-image
   ```

---

## HTTPS/HSTS: production vs local

- **Local** (exam/demo): runs on plain HTTP at `http://localhost:8080`. No HTTPS or HSTS is required.
- **Production**: `Program.cs` enables **HSTS** and **HTTPS redirection** automatically when `ASPNETCORE_ENVIRONMENT` is not `Development`.
- **Kubernetes**: use `k8s/ingress.dev.yaml` for an **HTTP-only** demo, or `k8s/ingress.yaml` for **HTTPS + HSTS** in production.

---

## CI/CD

- Push or open a Pull Request and GitHub Actions runs:
  - **build_test** – build + test (warnings as errors)
  - **codeql** – static analysis (C#)
  - **gitleaks** – secrets scanning
  - **trivy_fs** – filesystem vulnerability scan
  - **docker_build_scan** – build container and scan image

> Protect `main` and require all jobs green to merge.

---

## Kubernetes (optional demo)

```bash
kubectl apply -f k8s/namespace.yaml
kubectl -n mtogo create secret generic mtogo-secrets \  --from-literal=Jwt__Authority=https://issuer.example \  --from-literal=Jwt__Audience=mtogo \  --from-literal=ConnectionStrings__Default="Server=...;"
# For HTTP-only demo ingress
kubectl apply -f k8s/ingress.dev.yaml
# For HTTPS + HSTS (prod)
# kubectl -n mtogo create secret tls mtogo-tls --cert cert.crt --key key.key
# kubectl apply -f k8s/ingress.yaml
```

Replace the host if needed (e.g., `dev.localtest.me` resolves to 127.0.0.1).

---

## Notes for examiners

- JWT validation is **relaxed for local/demo** (no signing key) so tests can run with a synthetic token. In production, set `Jwt:Authority` and `Jwt:Audience` and enforce signature/lifetime validation.
- Secrets are kept **out of Git** (Kubernetes Secret + GitHub Secrets); Gitleaks prevents accidental commits.
- Trivy thresholds are set to **fail on HIGH/CRITICAL**.
