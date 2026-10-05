# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_ci_audit
==============================================================
Ejercita analizar_fichero() contra workflows YAML temporales completos.
"""

from pathlib import Path

import pytest

from vamp_ci_audit import analizar_fichero, encontrar_workflows


# ---------------------------------------------------------------------------
# Tests de integración (5 mínimos)
# ---------------------------------------------------------------------------

class TestIntegracionCiAudit:
    """Integración completa: fichero YAML → análisis → hallazgos."""

    def _crear_workflow(self, tmp_path, nombre, contenido):
        """Crea un fichero de workflow en la ruta estándar de GitHub Actions."""
        wdir = tmp_path / ".github" / "workflows"
        wdir.mkdir(parents=True, exist_ok=True)
        ruta = wdir / nombre
        ruta.write_text(contenido, encoding="utf-8")
        return ruta

    def test_expression_injection_genera_ci003(self, tmp_path):
        """
        Workflow con expression injection debe generar al menos un hallazgo CI-003 HIGH.
        """
        contenido = """\
name: CI vulnerable

on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Paso inseguro
        run: echo "${{ github.event.pull_request.title }}"
"""
        ruta = self._crear_workflow(tmp_path, "vulnerable.yml", contenido)
        hallazgos = analizar_fichero(ruta)
        ci003 = [h for h in hallazgos if h.id == "CI-003"]
        assert len(ci003) >= 1, "Se esperaba hallazgo CI-003 por expression injection"
        assert ci003[0].severidad == "HIGH"

    def test_secret_hardcodeado_genera_ci001(self, tmp_path):
        """
        Workflow con secret hardcodeado en env: debe generar CI-001 CRITICAL.
        """
        contenido = """\
name: Deploy

on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DATABASE_PASSWORD: supersecretpassword123
    steps:
      - run: ./deploy.sh
"""
        ruta = self._crear_workflow(tmp_path, "deploy.yml", contenido)
        hallazgos = analizar_fichero(ruta)
        ci001 = [h for h in hallazgos if h.id == "CI-001"]
        assert len(ci001) >= 1, "Se esperaba hallazgo CI-001 por secret hardcodeado"
        assert ci001[0].severidad == "CRITICAL"

    def test_action_sin_pin_genera_ci004(self, tmp_path):
        """
        Workflow con action referenciada por etiqueta mutable debe generar CI-004 HIGH.
        """
        contenido = """\
name: Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
"""
        ruta = self._crear_workflow(tmp_path, "build.yml", contenido)
        hallazgos = analizar_fichero(ruta)
        ci004 = [h for h in hallazgos if h.id == "CI-004"]
        assert len(ci004) >= 1, "Se esperaba hallazgo CI-004 por action sin SHA pin"

    def test_workflow_limpio_sin_hallazgos_criticos(self, tmp_path):
        """
        Workflow bien configurado no debe generar hallazgos CRITICAL o HIGH.
        """
        sha_checkout = "11bd71901bbe5b1630ceea73d27597364c9af683"
        contenido = f"""\
name: CI seguro

on: [push]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha_checkout}
      - name: Tests
        env:
          API_KEY: ${{{{ secrets.API_KEY }}}}
        run: pytest tests/
"""
        ruta = self._crear_workflow(tmp_path, "seguro.yml", contenido)
        hallazgos = analizar_fichero(ruta)
        criticos_altos = [h for h in hallazgos if h.severidad in ("CRITICAL", "HIGH")]
        assert len(criticos_altos) == 0, (
            f"Hallazgos inesperados: {[(h.id, h.severidad) for h in criticos_altos]}"
        )

    def test_encontrar_workflows_detecta_yaml(self, tmp_path):
        """
        encontrar_workflows debe encontrar los ficheros YAML en .github/workflows/.
        """
        wdir = tmp_path / ".github" / "workflows"
        wdir.mkdir(parents=True, exist_ok=True)
        (wdir / "ci.yml").write_text("name: CI\n", encoding="utf-8")
        (wdir / "deploy.yaml").write_text("name: Deploy\n", encoding="utf-8")

        ficheros = encontrar_workflows(tmp_path)
        nombres = [f.name for f in ficheros]
        assert "ci.yml" in nombres
        assert "deploy.yaml" in nombres
