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

## Licencia

AGPL-3.0-only — Ver [LICENSE](https://www.gnu.org/licenses/agpl-3.0.html)
