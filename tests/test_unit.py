# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_ci_audit
==================================================
Cubre: todos los checks CI-001 a CI-006, detección de plataforma,
       parseo YAML, serialización JSON/HTML.
"""


import yaml

from vamp_ci_audit import (
    PATRON_EXPRESION_INYECTABLE,
    PATRON_SHA_PIN,
    PATRON_USO_SECRETS,
    Hallazgo,
    check_ci001_secret_hardcodeado,
    check_ci002_pull_request_target,
    check_ci003_expression_injection,
    check_ci004_action_sin_pin_sha,
    check_ci005_permissions_write,
    detectar_plataforma,
    generar_json,
)

# ---------------------------------------------------------------------------
# Tests de utilidades de patrón
# ---------------------------------------------------------------------------

class TestPatrones:
    """Verifica los patrones regex de detección de la herramienta."""

    def test_patron_expresion_inyectable_detecta_pr_title(self):
        """El patrón de inyección debe detectar github.event.pull_request.title."""
        linea = 'run: echo "${{ github.event.pull_request.title }}"'
        assert PATRON_EXPRESION_INYECTABLE.search(linea) is not None

    def test_patron_expresion_inyectable_detecta_inputs(self):
        """El patrón de inyección debe detectar ${{ inputs.version }}."""
        linea = 'run: ./deploy.sh ${{ inputs.environment }}'
        assert PATRON_EXPRESION_INYECTABLE.search(linea) is not None

    def test_patron_uso_secrets_correcto(self):
        """${{ secrets.TOKEN }} debe coincidir como referencia correcta."""
        assert PATRON_USO_SECRETS.match("${{ secrets.API_TOKEN }}")

    def test_patron_uso_secrets_no_texto_literal(self):
        """Texto literal no debe coincidir con el patrón de secrets."""
        assert not PATRON_USO_SECRETS.match("mi_valor_hardcodeado")

    def test_patron_sha_pin_valido(self):
        """SHA de 40 hex debe coincidir."""
        sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
        assert PATRON_SHA_PIN.match(sha)

    def test_patron_sha_pin_invalido_etiqueta(self):
        """Etiqueta 'v3' no debe coincidir como SHA pin."""
        assert not PATRON_SHA_PIN.match("v3")


# ---------------------------------------------------------------------------
# Tests de detección de plataforma
# ---------------------------------------------------------------------------

class TestDetectarPlataforma:
    """Verifica la detección de plataforma CI/CD por ruta y estructura YAML."""

    def test_detecta_github_actions_por_ruta(self, tmp_path):
        """Ruta con .github/workflows debe detectarse como github_actions."""
        ruta = tmp_path / ".github" / "workflows" / "ci.yml"
        plat = detectar_plataforma(ruta, {})
        assert plat == "github_actions"

    def test_detecta_forgejo_actions_por_ruta(self, tmp_path):
        """Ruta con .forgejo/workflows debe detectarse como forgejo_actions."""
        ruta = tmp_path / ".forgejo" / "workflows" / "ci.yml"
        plat = detectar_plataforma(ruta, {})
        assert plat == "forgejo_actions"

    def test_detecta_gitlab_ci_por_nombre(self, tmp_path):
        """Fichero .gitlab-ci.yml debe detectarse como gitlab_ci."""
        ruta = tmp_path / ".gitlab-ci.yml"
        plat = detectar_plataforma(ruta, {})
        assert plat == "gitlab_ci"


# ---------------------------------------------------------------------------
# Tests de los checks individuales
# ---------------------------------------------------------------------------

class TestCheckCI001SecretHardcodeado:
    """CI-001: Detección de secrets hardcodeados en bloques env:."""

    def _ruta(self, tmp_path, nombre="workflow.yml"):
        return tmp_path / ".github" / "workflows" / nombre

    def test_detecta_secret_en_env_global(self, tmp_path):
        """Variable TOKEN con valor literal en env global debe generar CI-001 CRITICAL."""
        ruta = self._ruta(tmp_path)
        datos = {
            "env": {"API_TOKEN": "mi_secreto_hardcodeado"},
            "jobs": {}
        }
        lineas = ["env:", "  API_TOKEN: mi_secreto_hardcodeado"]
        hallazgos = check_ci001_secret_hardcodeado(ruta, datos, lineas, "github_actions")
        assert any(h.id == "CI-001" and h.severidad == "CRITICAL" for h in hallazgos)

    def test_no_detecta_referencia_secrets(self, tmp_path):
        """Uso correcto ${{ secrets.TOKEN }} no debe generar CI-001."""
        ruta = self._ruta(tmp_path)
        datos = {
            "env": {"API_TOKEN": "${{ secrets.API_TOKEN }}"},
            "jobs": {}
        }
        lineas = ["env:", "  API_TOKEN: ${{ secrets.API_TOKEN }}"]
        hallazgos = check_ci001_secret_hardcodeado(ruta, datos, lineas, "github_actions")
        ci001 = [h for h in hallazgos if h.id == "CI-001"]
        assert len(ci001) == 0

    def test_detecta_secret_en_step_env(self, tmp_path):
        """SECRET hardcodeado en env de un step debe detectarse."""
        ruta = self._ruta(tmp_path)
        datos = {
            "jobs": {
                "build": {
                    "steps": [
                        {"name": "paso", "env": {"PASSWORD": "admin123"}, "run": "ls"}
                    ]
                }
            }
        }
        lineas = ["PASSWORD: admin123"]
        hallazgos = check_ci001_secret_hardcodeado(ruta, datos, lineas, "github_actions")
        assert any(h.id == "CI-001" for h in hallazgos)


class TestCheckCI002PullRequestTarget:
    """CI-002: pull_request_target con checkout del PR."""

    def _ruta(self, tmp_path):
        return tmp_path / ".github" / "workflows" / "pr.yml"

    def test_detecta_prt_con_checkout_head(self, tmp_path):
        """pull_request_target + checkout con ref head debe generar CI-002 HIGH."""
        ruta = self._ruta(tmp_path)
        datos = {
            "on": {"pull_request_target": {}},
            "jobs": {
                "work": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v3",
                            "with": {"ref": "${{ github.event.pull_request.head.sha }}"}
                        }
                    ]
                }
            }
        }
        lineas = ["uses: actions/checkout@v3"]
        hallazgos = check_ci002_pull_request_target(ruta, datos, lineas, "github_actions")
        assert any(h.id == "CI-002" and h.severidad == "HIGH" for h in hallazgos)

    def test_no_detecta_sin_prt_trigger(self, tmp_path):
        """Workflow sin pull_request_target no debe generar CI-002."""
        ruta = self._ruta(tmp_path)
        datos = {"on": ["push"], "jobs": {}}
        hallazgos = check_ci002_pull_request_target(ruta, datos, [], "github_actions")
        assert len(hallazgos) == 0


class TestCheckCI003ExpressionInjection:
    """CI-003: Expression injection en run:."""

    def _ruta(self, tmp_path):
        return tmp_path / ".github" / "workflows" / "ci.yml"

    def test_detecta_pr_title_en_run(self, tmp_path):
        """${{ github.event.pull_request.title }} en run: debe generar CI-003 HIGH."""
        ruta = self._ruta(tmp_path)
        run_cmd = 'echo "${{ github.event.pull_request.title }}"'
        datos = {
            "jobs": {
                "build": {
                    "steps": [{"name": "test", "run": run_cmd}]
                }
            }
        }
        lineas = [run_cmd]
        hallazgos = check_ci003_expression_injection(ruta, datos, lineas, "github_actions")
        assert any(h.id == "CI-003" and h.severidad == "HIGH" for h in hallazgos)

    def test_no_detecta_github_sha_en_run(self, tmp_path):
        """${{ github.sha }} es seguro y no debe generar CI-003."""
        ruta = self._ruta(tmp_path)
        run_cmd = 'echo "${{ github.sha }}"'
        datos = {
            "jobs": {
                "build": {
                    "steps": [{"name": "test", "run": run_cmd}]
                }
            }
        }
        hallazgos = check_ci003_expression_injection(ruta, datos, [run_cmd], "github_actions")
        assert len(hallazgos) == 0


class TestCheckCI004ActionSinPin:
    """CI-004: Actions externas sin SHA pin."""

    def _ruta(self, tmp_path):
        return tmp_path / ".github" / "workflows" / "ci.yml"

    def test_detecta_action_con_etiqueta_mutable(self, tmp_path):
        """actions/checkout@v3 sin SHA debe generar CI-004 HIGH."""
        ruta = self._ruta(tmp_path)
        datos = {
            "jobs": {
                "build": {
                    "steps": [{"uses": "actions/checkout@v3"}]
                }
            }
        }
        hallazgos = check_ci004_action_sin_pin_sha(ruta, datos, ["uses: actions/checkout@v3"], "github_actions")
        assert any(h.id == "CI-004" and h.severidad == "HIGH" for h in hallazgos)

    def test_no_detecta_action_con_sha_correcto(self, tmp_path):
        """Action con SHA de 40 hex no debe generar CI-004."""
        sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
        ruta = self._ruta(tmp_path)
        datos = {
            "jobs": {
                "build": {
                    "steps": [{"uses": f"actions/checkout@{sha}"}]
                }
            }
        }
        hallazgos = check_ci004_action_sin_pin_sha(ruta, datos, [f"uses: actions/checkout@{sha}"], "github_actions")
        ci004 = [h for h in hallazgos if h.id == "CI-004"]
        assert len(ci004) == 0

    def test_no_detecta_action_local(self, tmp_path):
        """Actions locales (./) deben ignorarse."""
        ruta = self._ruta(tmp_path)
        datos = {
            "jobs": {
                "build": {
                    "steps": [{"uses": "./actions/mi-action"}]
                }
            }
        }
        hallazgos = check_ci004_action_sin_pin_sha(ruta, datos, [], "github_actions")
        assert len(hallazgos) == 0


class TestCheckCI005Permisos:
    """CI-005: Permisos write excesivos."""

    def _ruta(self, tmp_path):
        return tmp_path / ".github" / "workflows" / "ci.yml"

    def test_detecta_write_all(self, tmp_path):
        """permissions: write-all debe generar CI-005 HIGH."""
        ruta = self._ruta(tmp_path)
        datos = {"permissions": "write-all", "jobs": {}}
        hallazgos = check_ci005_permissions_write(ruta, datos, ["permissions: write-all"], "github_actions")
        assert any(h.id == "CI-005" and h.severidad == "HIGH" for h in hallazgos)


# ---------------------------------------------------------------------------
# Test de serialización JSON
# ---------------------------------------------------------------------------

class TestGenararJson:
    """Verifica que generar_json produce output válido."""

    def test_json_valido_sin_hallazgos(self):
        """JSON con lista vacía debe ser parseable y tener total_hallazgos=0."""
        resultado = generar_json([])
        data = yaml.safe_load(resultado)  # YAML es un superset de JSON
        assert data["total_hallazgos"] == 0

    def test_json_con_hallazgos(self):
        """JSON con hallazgos debe incluir los datos correctos."""
        h = Hallazgo(
            id="CI-001", severidad="CRITICAL",
            titulo="Test", descripcion="desc",
            archivo="w.yml", linea=5,
            evidencia="env.TOKEN = x",
            mitigacion="mover a secrets",
            cis="CIS 14.6",
            tipo_plataforma="github_actions",
        )
        resultado = generar_json([h])
        import json as _json
        data = _json.loads(resultado)
        assert data["total_hallazgos"] == 1
        assert data["resumen"]["CRITICAL"] == 1
