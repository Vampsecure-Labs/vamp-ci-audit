# vamp-ci-audit

  <img src="https://github.com/Vampsecure-Labs/vamp-ci-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>

**CI/CD pipeline security auditor** — GitHub Actions, GitLab CI and Forgejo Actions

© VampSecure Studios — VampSecure Labs Security Research Division  
Para Uso Exclusivo en Pruebas de Penetración Autorizadas

## Instalación

```bash
pip install vamp-ci-audit
```

## Uso

```bash
# Escanear directorio actual (busca workflows automáticamente)
vamp-ci-audit scan .

# Escanear workflows de GitHub Actions
vamp-ci-audit scan .github/workflows/

# Escanear un fichero concreto
vamp-ci-audit scan workflow.yml

# Salida JSON
vamp-ci-audit scan . --format json

# Informe HTML
vamp-ci-audit scan . --output informe.html

# Solo hallazgos HIGH y CRITICAL
vamp-ci-audit scan . --severity HIGH
```

## Checks incluidos

| ID     | Severidad | Descripción |
|--------|-----------|-------------|
| CI-001 | CRITICAL  | Secret hardcodeado en bloque `env:` |
| CI-002 | HIGH      | `pull_request_target` con checkout de código del PR |
| CI-003 | HIGH      | Expression injection — variable controlable en `run:` |
| CI-004 | HIGH      | Action externa sin SHA pin (ref mutable) |
| CI-005 | HIGH      | Permisos `write-all` o write en scopes sensibles |
| CI-006 | MEDIUM    | Self-hosted runner sin label de restricción |
| CI-007 | MEDIUM    | Ruta de artefacto con expresión controlable por atacante |
| CI-008 | MEDIUM    | Cache key con rama/PR controlable (cache poisoning) |
| CI-009 | MEDIUM    | Input `workflow_dispatch` sin validación en `run:` |
| CI-010 | LOW       | GITHUB_TOKEN con `write` innecesario en job de build/test |

## Plataformas soportadas

- GitHub Actions (`.github/workflows/*.yml`)
- GitLab CI (`.gitlab-ci.yml`)
- Forgejo Actions (`.forgejo/workflows/*.yml`)

## Exit codes

- `0` — Sin hallazgos
- `1` — Hallazgos encontrados
- `2` — Error de ejecución

## Sample Output

```bash
$ vamp-ci-audit scan .github/workflows/
  vamp-ci-audit v1.0 — CI/CD Pipeline Security Auditor
  Scanning: .github/workflows/ (3 files found)
  ────────────────────────────────────────────────────────────

  [CRITICAL] CI-001 — .github/workflows/deploy.yml:14
    Secret hardcoded in env block: AWS_SECRET_KEY=AKIA...redacted
    Fix: Use ${{ secrets.AWS_SECRET_KEY }} and store in repository secrets

  [HIGH] CI-002 — .github/workflows/pr-check.yml:8
    pull_request_target with checkout of PR code (MITRE ATT&CK T1195.002)
    Fix: Use pull_request trigger, or restrict checkout to base ref only

  [HIGH] CI-003 — .github/workflows/ci.yml:27
    Expression injection: run: echo ${{ github.event.issue.title }}
    Fix: Assign to env var first — env: TITLE: ${{ ... }} — reference via $TITLE

  ────────────────────────────────────────────────────────────
  Files scanned: 3 | Findings: 3 | CRITICAL: 1 | HIGH: 2 | MEDIUM: 0
  Exit code: 1
```

## Why vamp-ci-audit vs. GitGuardian CI · Semgrep CI rules · OWASP Pipeline Security

| Feature | vamp-ci-audit | GitGuardian CI | Semgrep CI rules |
|---------|:-------------:|:--------------:|:----------------:|
| Forgejo Actions support | ✅ | ❌ | ❌ |
| `pull_request_target` injection detection | ✅ | ❌ | ⚠️ community rules |
| SHA hash-pin enforcement (SLSA L2) | ✅ | ❌ | ⚠️ partial |
| Self-hosted runner label analysis | ✅ | ❌ | ❌ |
| MITRE ATT&CK T1195.002 mapping | ✅ | ❌ | ❌ |
| CIS Software Supply Chain alignment | ✅ | ❌ | ❌ |
| No cloud / no SaaS dependency | ✅ | ❌ SaaS | ✅ |
| Cache poisoning detection (CI-008) | ✅ | ❌ | ❌ |
| Standalone install (no server) | ✅ `pip install` | ❌ | ✅ |

- **Self-hosted first**: zero telemetry, no pipeline data ever leaves the machine — critical for air-gapped CI environments.
- **Forgejo-native**: the only open-source auditor with explicit `.forgejo/workflows/` support alongside GitHub Actions and GitLab CI.
- **SLSA-aligned**: hash-pin enforcement is a first-class check, not an afterthought — aligns with SLSA Supply Chain Levels 2 and 3.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| CI-001 | Secret hardcoded in `env:` block of workflow | CIS SC 1.1 | CRITICAL |
| CI-002 | `pull_request_target` trigger with checkout of PR code | SLSA L2 · ATT&CK T1195.002 | HIGH |
| CI-003 | Expression injection via `run:` with user-controlled context | OWASP Pipeline Top 10 A5 | HIGH |
| CI-004 | Action pinned to mutable ref (branch or tag, not SHA) | SLSA L2 · CIS SC 1.6 | HIGH |
| CI-005 | `write-all` permissions or write access to sensitive scopes | CIS SC 4.3 | HIGH |
| CI-006 | Self-hosted runner without restrictive label | CIS SC 6.2 | MEDIUM |
| CI-007 | Artifact upload/download path with attacker-controlled expression | OWASP Pipeline Top 10 A6 | MEDIUM |
| CI-008 | Cache key includes branch name or PR number (cache poisoning) | CIS SC 5.1 | MEDIUM |
| CI-009 | Unvalidated `workflow_dispatch` input interpolated into `run:` | OWASP Pipeline Top 10 A5 | MEDIUM |
| CI-010 | GITHUB_TOKEN scoped `write` on a build or test job | CIS SC 4.1 | LOW |

## Licencia

AGPL-3.0-only — Ver [LICENSE](https://www.gnu.org/licenses/agpl-3.0.html)
