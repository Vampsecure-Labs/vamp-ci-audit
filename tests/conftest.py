# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-ci-audit
"""

import sys
from pathlib import Path

import pytest

# Añadir directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures de contenido YAML de prueba
# ---------------------------------------------------------------------------

@pytest.fixture
def yaml_expression_injection():
    """Workflow con expression injection en un step run:."""
    return """\
name: CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Paso vulnerable
        run: echo "PR title is ${{ github.event.pull_request.title }}"
"""


@pytest.fixture
def yaml_secret_hardcodeado():
    """Workflow con secret hardcodeado en bloque env:."""
    return """\
name: Deploy

on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_TOKEN: mi_secreto_super_privado
    steps:
      - name: Desplegar
        run: ./deploy.sh
"""


@pytest.fixture
def yaml_action_sin_pin():
    """Workflow con action sin SHA pin (usa etiqueta mutable v3)."""
    return """\
name: Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
"""


@pytest.fixture
def yaml_pull_request_target_peligroso():
    """Workflow con pull_request_target y checkout del código del PR."""
    return """\
name: Auto-label

on:
  pull_request_target:
    types: [opened]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./label.sh
"""


@pytest.fixture
def yaml_limpio():
    """Workflow sin ninguna vulnerabilidad conocida."""
    return """\
name: CI limpio

on: [push]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Ejecutar tests
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: pytest
"""


@pytest.fixture
def yaml_permisos_write_all():
    """Workflow con permissions: write-all."""
    return """\
name: Write All

on: [push]

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: echo ok
"""
