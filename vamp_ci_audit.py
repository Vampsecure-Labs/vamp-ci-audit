#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_ci_audit.py — Auditor de seguridad de pipelines CI/CD
Detecta: secrets expuestos, privilege escalation, dependency pinning,
pull_request_target abuse, injection de expresiones, actions no pinadas.

VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml no está instalado. Instala con: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    print("ERROR: rich no está instalado. Instala con: pip install rich", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Constantes y configuración
# ---------------------------------------------------------------------------

HERRAMIENTA_VERSION = "1.0"
HERRAMIENTA_NOMBRE = "vamp-ci-audit"

# Colores por severidad para la consola Rich
COLORES_SEVERIDAD: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}

# Patrones de nombres de variables que sugieren secretos
PATRON_NOMBRES_SECRETO = re.compile(
    r"(?i)(TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|PRIVATE|CREDENTIAL|AWS_SECRET|"
    r"ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|DB_PASS|DATABASE_PASSWORD|"
    r"WEBHOOK|SIGNING_KEY|ENCRYPTION_KEY|PRIVATE_KEY|PGP_KEY)"
)

# Patrón para detectar uso correcto de secrets (referencia a secrets.X)
PATRON_USO_SECRETS = re.compile(r"^\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}$")

# Patrón para detectar SHA pin válido (40 caracteres hexadecimales)
PATRON_SHA_PIN = re.compile(r"^[0-9a-fA-F]{40}$")

# Patrón para detectar referencias a eventos de PR controlables por atacante
PATRON_EXPRESION_PR_CONTROLABLE = re.compile(
    r"\$\{\{[^}]*github\.event\.(pull_request\.(title|body|head\.ref|base\.ref)|"
    r"issue\.(title|body)|comment\.body|discussion\.(title|body))[^}]*\}\}"
)

# Patrón para detectar expresiones inyectables en run: (cualquier github.event o inputs sin sanitizar)
PATRON_EXPRESION_INYECTABLE = re.compile(
    r"\$\{\{[^}]*("
    r"github\.event\.(pull_request\.(title|body|head\.ref|base\.ref|head\.label)|"
    r"issue\.(title|body)|comment\.body|discussion\.body)|"
    r"inputs\.[A-Za-z0-9_]+"
    r")[^}]*\}\}"
)

# Severidades válidas para filtrado
SEVERIDADES_VALIDAS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ORDEN_SEVERIDAD: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}


# ---------------------------------------------------------------------------
# Estructura de datos de hallazgo
# ---------------------------------------------------------------------------

@dataclass
class Hallazgo:
    """Representa un hallazgo de seguridad encontrado en un pipeline CI/CD."""
    id: str
    severidad: str
    titulo: str
    descripcion: str
    archivo: str
    linea: int
    evidencia: str
    mitigacion: str
    cis: str
    tipo_plataforma: str = "desconocido"


# ---------------------------------------------------------------------------
# Detección de plataforma CI/CD
# ---------------------------------------------------------------------------

def detectar_plataforma(ruta: Path, datos_yaml: dict) -> str:
    """
    Detecta la plataforma CI/CD basándose en la ruta del fichero y estructura YAML.
    Soporta GitHub Actions, GitLab CI y Forgejo Actions.
    """
    ruta_str = str(ruta)

    # GitHub Actions: .github/workflows/
    if ".github/workflows" in ruta_str:
        return "github_actions"

    # Forgejo Actions: .forgejo/workflows/
    if ".forgejo/workflows" in ruta_str:
        return "forgejo_actions"

    # GitLab CI: .gitlab-ci.yml
    if ruta.name in (".gitlab-ci.yml", "gitlab-ci.yml"):
        return "gitlab_ci"

    # Intentar detectar por estructura YAML
    if isinstance(datos_yaml, dict):
        # GitHub/Forgejo Actions tienen clave "on:" o "jobs:"
        if "on" in datos_yaml or "jobs" in datos_yaml:
            # Comprobar si tiene estructura de job típica de GitHub/Forgejo
            jobs = datos_yaml.get("jobs", {})
            if isinstance(jobs, dict):
                return "github_actions"

        # GitLab CI suele tener stages: o default:
        if "stages" in datos_yaml or "default" in datos_yaml:
            return "gitlab_ci"

    return "desconocido"


# ---------------------------------------------------------------------------
# Utilidades de análisis YAML
# ---------------------------------------------------------------------------

def obtener_linea_clave(lineas: list[str], clave: str, desde_linea: int = 0) -> int:
    """Busca el número de línea (1-based) donde aparece una clave en el YAML fuente."""
    for i, linea in enumerate(lineas[desde_linea:], start=desde_linea + 1):
        if clave in linea:
            return i
    return desde_linea + 1


def buscar_patron_en_lineas(lineas: list[str], patron: re.Pattern,
                             desde_linea: int = 0) -> Iterator[tuple[int, str]]:
    """
    Itera sobre las líneas buscando el patrón dado.
    Devuelve (número_linea_1based, texto_linea).
    """
    for i, linea in enumerate(lineas[desde_linea:], start=desde_linea + 1):
        if patron.search(linea):
            yield i, linea.strip()


# ---------------------------------------------------------------------------
# Checks de seguridad CI-001 a CI-010
# ---------------------------------------------------------------------------

def check_ci001_secret_hardcodeado(ruta: Path, datos: dict,
                                    lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-001 CRITICAL: Detecta secrets hardcodeados en bloques env:.
    Un secret hardcodeado es cuando la clave tiene nombre sospechoso
    (TOKEN, PASSWORD, etc.) y el valor no es ${{ secrets.X }}.
    """
    hallazgos: list[Hallazgo] = []

    def analizar_env_dict(env_dict: dict, contexto: str = "") -> None:
        """Analiza un diccionario env: buscando valores sospechosos."""
        if not isinstance(env_dict, dict):
            return
        for clave, valor in env_dict.items():
            if not isinstance(clave, str):
                continue
            if PATRON_NOMBRES_SECRETO.search(clave):
                valor_str = str(valor) if valor is not None else ""
                # Valor vacío es aceptable
                if not valor_str:
                    continue
                # Valor correcto: ${{ secrets.ALGO }}
                if PATRON_USO_SECRETS.match(valor_str.strip()):
                    continue
                # Valor ${{ env.ALGO }} tampoco es hardcodeado
                if re.match(r"^\$\{\{\s*env\.[A-Za-z0-9_]+\s*\}\}$", valor_str.strip()):
                    continue
                # Detección de posible secret hardcodeado
                num_linea = obtener_linea_clave(lineas, clave)
                evidencia = f"env.{clave} = {valor_str[:80]}"
                hallazgos.append(Hallazgo(
                    id="CI-001",
                    severidad="CRITICAL",
                    titulo="Secret hardcodeado en bloque env:",
                    descripcion=(
                        f"La variable de entorno '{clave}' tiene un nombre que sugiere "
                        f"credencial sensible pero su valor no proviene de "
                        f"${{{{ secrets.X }}}} sino de texto literal o variable directa. "
                        f"Esto expone el secreto en los logs del pipeline y en el código fuente."
                    ),
                    archivo=str(ruta),
                    linea=num_linea,
                    evidencia=evidencia,
                    mitigacion=(
                        f"Mover el valor a GitHub Secrets/GitLab CI Variables y referenciar "
                        f"con ${{{{ secrets.{clave} }}}}. Revocar y rotar el secreto actual."
                    ),
                    cis="CIS Control 14.6 — Proteger información sensible a través de cifrado",
                    tipo_plataforma=plataforma,
                ))

    # GitHub/Forgejo Actions: buscar en jobs > steps > env y en env global
    if plataforma in ("github_actions", "forgejo_actions"):
        # env global del workflow
        env_global = datos.get("env", {})
        if isinstance(env_global, dict):
            analizar_env_dict(env_global, "global")

        # env por job y por step
        jobs = datos.get("jobs", {})
        if isinstance(jobs, dict):
            for nombre_job, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                analizar_env_dict(job.get("env", {}), f"job:{nombre_job}")
                steps = job.get("steps", [])
                if isinstance(steps, list):
                    for step in steps:
                        if isinstance(step, dict):
                            analizar_env_dict(step.get("env", {}),
                                              f"job:{nombre_job}/step")

    # GitLab CI: buscar en variables: a nivel global y por job
    elif plataforma == "gitlab_ci":
        vars_global = datos.get("variables", {})
        if isinstance(vars_global, dict):
            analizar_env_dict(vars_global, "global")
        for nombre_job, job in datos.items():
            if isinstance(job, dict) and "variables" in job:
                analizar_env_dict(job["variables"], f"job:{nombre_job}")

    return hallazgos


def check_ci002_pull_request_target(ruta: Path, datos: dict,
                                     lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-002 HIGH: Detecta uso de pull_request_target con checkout del código del PR.
    Esto permite que código de forks acceda a secrets del repositorio base.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    # Verificar si el trigger es pull_request_target
    on_config = datos.get("on", datos.get(True, {}))  # 'on' puede parsearse como True en YAML
    if not on_config:
        return hallazgos

    trigger_prt = False
    if isinstance(on_config, dict):
        trigger_prt = "pull_request_target" in on_config
    elif isinstance(on_config, list):
        trigger_prt = "pull_request_target" in on_config
    elif isinstance(on_config, str):
        trigger_prt = on_config == "pull_request_target"

    if not trigger_prt:
        return hallazgos

    # Buscar si algún step hace checkout con ref del PR (comportamiento peligroso)
    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            with_params = step.get("with", {})

            # Detectar actions/checkout con ref apuntando al PR
            if isinstance(uses, str) and "actions/checkout" in uses:
                if isinstance(with_params, dict):
                    ref = str(with_params.get("ref", ""))
                    if "head" in ref.lower() or "pr" in ref.lower() or \
                       "pull_request" in ref.lower() or "github.event" in ref:
                        num_linea = obtener_linea_clave(lineas, "actions/checkout")
                        hallazgos.append(Hallazgo(
                            id="CI-002",
                            severidad="HIGH",
                            titulo="pull_request_target con checkout de código del PR",
                            descripcion=(
                                "El workflow usa pull_request_target (que tiene acceso a secrets) "
                                "y hace checkout del código del fork/PR con ref apuntando al HEAD "
                                "del PR. Esto permite a cualquier fork ejecutar código arbitrario "
                                "con acceso a todos los secrets del repositorio base."
                            ),
                            archivo=str(ruta),
                            linea=num_linea,
                            evidencia=f"uses: {uses} con ref: {ref}",
                            mitigacion=(
                                "Nunca hacer checkout del código del PR en un workflow "
                                "pull_request_target. Si necesitas analizar el código del PR, "
                                "descárgalo como artefacto desde un workflow separado sin acceso "
                                "a secrets, o usa actions/checkout sin especificar ref."
                            ),
                            cis="CIS Control 18.3 — Verificar la integridad del software",
                            tipo_plataforma=plataforma,
                        ))

    return hallazgos


def check_ci003_expression_injection(ruta: Path, datos: dict,
                                      lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-003 HIGH: Detecta inyección de expresiones en comandos run:.
    Uso directo de variables controladas por el atacante (título de PR, body, etc.)
    en comandos shell sin sanitizar.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if not isinstance(run, str):
                continue

            # Buscar expresiones inyectables en el comando run
            matches = PATRON_EXPRESION_INYECTABLE.findall(run)
            if matches:
                # Encontrar el número de línea
                num_linea = obtener_linea_clave(lineas, run[:40] if len(run) > 40 else run)
                # Limitar evidencia para legibilidad
                evidencia_run = run[:120] + ("..." if len(run) > 120 else "")
                hallazgos.append(Hallazgo(
                    id="CI-003",
                    severidad="HIGH",
                    titulo="Expression injection — variable controlable por atacante en run:",
                    descripcion=(
                        "El comando run: contiene una expresión de GitHub Actions que referencia "
                        "datos controlados por el atacante (título de PR, body, head.ref, etc.) "
                        "directamente en un comando shell. Un atacante puede crear un PR con "
                        "un título que incluya comandos shell para ejecutar código arbitrario."
                    ),
                    archivo=str(ruta),
                    linea=num_linea,
                    evidencia=f"run: {evidencia_run}",
                    mitigacion=(
                        "Asignar el valor a una variable de entorno intermedia y referenciar "
                        "la variable de entorno en el script (env: PR_TITLE: ${{ ... }}, "
                        "luego usar $PR_TITLE en el script). Las variables de entorno no "
                        "son interpretadas como código shell."
                    ),
                    cis="CIS Control 18.5 — Usar análisis de código estático",
                    tipo_plataforma=plataforma,
                ))

    return hallazgos


def check_ci004_action_sin_pin_sha(ruta: Path, datos: dict,
                                    lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-004 HIGH: Detecta actions externas sin SHA pin.
    Usar @v1 o @main en vez de @abc123def (commit SHA de 40 chars) permite
    supply chain attacks si el repositorio de la action es comprometido.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if not isinstance(uses, str) or not uses:
                continue

            # Ignorar actions locales (./ prefix)
            if uses.startswith("./"):
                continue

            # Extraer el ref (después del @)
            partes = uses.rsplit("@", 1)
            if len(partes) != 2:
                continue

            accion_nombre, ref = partes
            ref = ref.strip()

            # Comprobar si es un SHA válido de 40 caracteres
            if PATRON_SHA_PIN.match(ref):
                continue  # Correcto: está pinada a un SHA

            # No está pinada: es una etiqueta, rama u otro ref mutable
            num_linea = obtener_linea_clave(lineas, uses)
            hallazgos.append(Hallazgo(
                id="CI-004",
                severidad="HIGH",
                titulo="Action externa sin SHA pin — ref mutable",
                descripcion=(
                    f"La action '{accion_nombre}' usa el ref '{ref}' que es mutable "
                    f"(etiqueta, rama). Si el repositorio de la action es comprometido, "
                    f"un atacante puede modificar el código que se ejecuta en tu pipeline "
                    f"sin que tú lo notes (supply chain attack)."
                ),
                archivo=str(ruta),
                linea=num_linea,
                evidencia=f"uses: {uses}",
                mitigacion=(
                    f"Reemplazar el ref mutable por el SHA completo del commit: "
                    f"uses: {accion_nombre}@<sha40chars>. "
                    f"Herramientas como 'pin-github-action' o 'mheap/pin-github-action' "
                    f"pueden automatizar esto. Mantener un registro de las versiones usadas."
                ),
                cis="CIS Control 18.2 — Asegurar que los componentes software son auténticos",
                tipo_plataforma=plataforma,
            ))

    return hallazgos


def check_ci005_permissions_write(ruta: Path, datos: dict,
                                   lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-005 HIGH: Detecta permisos write-all o write en scopes sensibles
    cuando el workflow parece ser solo de build/test.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    # Scopes de permiso que son especialmente sensibles si están en write
    SCOPES_SENSIBLES = {"contents", "packages", "id-token", "deployments", "environments"}

    def analizar_permisos(permisos: dict | str, contexto: str, num_linea: int) -> None:
        """Analiza una sección permissions: buscando write en scopes sensibles."""
        if permisos == "write-all":
            hallazgos.append(Hallazgo(
                id="CI-005",
                severidad="HIGH",
                titulo=f"Permisos write-all en {contexto}",
                descripcion=(
                    "El workflow tiene permisos write-all, concediendo acceso de escritura "
                    "a todos los scopes de GitHub token. Siguiendo el principio de mínimo "
                    "privilegio, los workflows deberían declarar solo los permisos estrictamente "
                    "necesarios."
                ),
                archivo=str(ruta),
                linea=num_linea,
                evidencia=f"permissions: write-all en {contexto}",
                mitigacion=(
                    "Reemplazar write-all por la lista explícita de permisos mínimos necesarios. "
                    "Para un workflow de build/test, 'contents: read' suele ser suficiente."
                ),
                cis="CIS Control 6.3 — Mínimo privilegio de cuentas",
                tipo_plataforma=plataforma,
            ))
        elif isinstance(permisos, dict):
            for scope, nivel in permisos.items():
                if scope in SCOPES_SENSIBLES and nivel == "write":
                    hallazgos.append(Hallazgo(
                        id="CI-005",
                        severidad="HIGH",
                        titulo=f"Permiso write en scope sensible '{scope}'",
                        descripcion=(
                            f"El scope '{scope}' tiene nivel 'write'. Este permiso permite "
                            f"modificar contenido del repositorio, publicar paquetes o crear "
                            f"tokens de identidad OIDC según el scope. Verificar si es "
                            f"realmente necesario para el workflow."
                        ),
                        archivo=str(ruta),
                        linea=num_linea,
                        evidencia=f"permissions.{scope}: write en {contexto}",
                        mitigacion=(
                            f"Revisar si el workflow necesita {scope}: write. Si es solo "
                            f"para leer, usar {scope}: read. Si no lo necesita, eliminarlo."
                        ),
                        cis="CIS Control 6.3 — Mínimo privilegio de cuentas",
                        tipo_plataforma=plataforma,
                    ))

    # Permisos globales del workflow
    permisos_global = datos.get("permissions")
    if permisos_global:
        num_linea = obtener_linea_clave(lineas, "permissions:")
        analizar_permisos(permisos_global, "workflow global", num_linea)

    # Permisos por job
    jobs = datos.get("jobs", {})
    if isinstance(jobs, dict):
        for nombre_job, job in jobs.items():
            if not isinstance(job, dict):
                continue
            permisos_job = job.get("permissions")
            if permisos_job:
                num_linea = obtener_linea_clave(lineas, "permissions:")
                analizar_permisos(permisos_job, f"job:{nombre_job}", num_linea)

    return hallazgos


def check_ci006_self_hosted_runner(ruta: Path, datos: dict,
                                    lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-006 MEDIUM: Detecta self-hosted runner sin labels adicionales de restricción.
    Un runner genérico 'self-hosted' puede ejecutar en cualquier runner disponible,
    incluyendo runners compartidos no aislados.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue

        runs_on = job.get("runs-on")
        if not runs_on:
            continue

        # Detectar si usa self-hosted sin labels adicionales
        es_solo_self_hosted = False
        if runs_on == "self-hosted":
            es_solo_self_hosted = True
        elif isinstance(runs_on, list):
            # Lista con solo 'self-hosted' o con labels genéricas sin especificar entorno
            labels_normalizadas = [str(l).lower().strip() for l in runs_on]
            if "self-hosted" in labels_normalizadas and len(labels_normalizadas) <= 2:
                # Comprobar si los labels adicionales son genéricos (linux/windows/macos)
                labels_genericas = {"linux", "windows", "macos", "x64", "arm64", "x86"}
                otros_labels = set(labels_normalizadas) - {"self-hosted"} - labels_genericas
                if not otros_labels:
                    es_solo_self_hosted = True

        if es_solo_self_hosted:
            num_linea = obtener_linea_clave(lineas, "runs-on:")
            hallazgos.append(Hallazgo(
                id="CI-006",
                severidad="MEDIUM",
                titulo=f"Self-hosted runner sin label de restricción en job:{nombre_job}",
                descripcion=(
                    "El job usa 'self-hosted' sin labels adicionales específicos del entorno "
                    "empresarial. En organizaciones con múltiples runners, esto puede permitir "
                    "que el job ejecute en cualquier runner disponible, incluyendo runners "
                    "compartidos o de baja confianza. En contextos de fork/PR, puede ejecutar "
                    "código arbitrario en infraestructura interna."
                ),
                archivo=str(ruta),
                linea=num_linea,
                evidencia=f"runs-on: {runs_on} en job:{nombre_job}",
                mitigacion=(
                    "Añadir labels específicos del entorno: runs-on: [self-hosted, production, "
                    "isolated]. Asegurarse de que los runners self-hosted para workflows de PR "
                    "están aislados y no tienen acceso a secrets de producción."
                ),
                cis="CIS Control 4.7 — Gestionar la configuración del sistema",
                tipo_plataforma=plataforma,
            ))

    return hallazgos


def check_ci007_artifact_path_controlable(ruta: Path, datos: dict,
                                           lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-007 MEDIUM: Detecta rutas de artefactos con expresiones controlables por el atacante.
    Puede permitir path traversal o sobrescritura de artefactos legítimos.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    PATRON_EVENTO_EN_PATH = re.compile(
        r"\$\{\{[^}]*github\.event\.[^}]+\}\}"
    )

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            with_params = step.get("with", {})

            if not isinstance(uses, str) or "upload-artifact" not in uses.lower():
                continue

            if not isinstance(with_params, dict):
                continue

            path = str(with_params.get("path", ""))
            name = str(with_params.get("name", ""))

            # Comprobar si path o name contiene expresiones de eventos
            for campo, valor in [("path", path), ("name", name)]:
                if PATRON_EVENTO_EN_PATH.search(valor):
                    num_linea = obtener_linea_clave(lineas, "upload-artifact")
                    hallazgos.append(Hallazgo(
                        id="CI-007",
                        severidad="MEDIUM",
                        titulo=f"Ruta de artefacto controlable por atacante ({campo}:)",
                        descripcion=(
                            f"El campo '{campo}' de upload-artifact contiene una expresión "
                            f"basada en datos del evento (github.event.*) que puede ser "
                            f"controlada por un atacante. Esto puede causar path traversal, "
                            f"sobrescritura de artefactos o comportamiento inesperado."
                        ),
                        archivo=str(ruta),
                        linea=num_linea,
                        evidencia=f"{campo}: {valor[:80]}",
                        mitigacion=(
                            f"Evitar usar datos del evento directamente en rutas de artefactos. "
                            f"Usar valores estáticos o expresiones controladas como "
                            f"github.run_id o github.sha para nombres únicos."
                        ),
                        cis="CIS Control 18.5 — Usar análisis de código estático",
                        tipo_plataforma=plataforma,
                    ))

    return hallazgos


def check_ci008_cache_key_controlable(ruta: Path, datos: dict,
                                       lineas: list[str], plataforma: str) -> list[Hallazgo]:
    """
    CI-008 MEDIUM: Detecta claves de caché que incluyen datos controlables por el atacante.
    Un atacante puede envenenar la caché de otro job/PR usando una clave predecible.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    PATRON_REF_CONTROLABLE_CACHE = re.compile(
        r"\$\{\{[^}]*(github\.head_ref|github\.event\.pull_request\.[^}]+)[^}]*\}\}"
    )

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            with_params = step.get("with", {})

            if not isinstance(uses, str) or "cache" not in uses.lower():
                continue

            if not isinstance(with_params, dict):
                continue

            key = str(with_params.get("key", ""))
            restore_keys = str(with_params.get("restore-keys", ""))

            for campo, valor in [("key", key), ("restore-keys", restore_keys)]:
                if not valor:
                    continue
                if PATRON_REF_CONTROLABLE_CACHE.search(valor):
                    num_linea = obtener_linea_clave(lineas, "cache")
                    hallazgos.append(Hallazgo(
                        id="CI-008",
                        severidad="MEDIUM",
                        titulo=f"Cache key controlable por atacante — envenenamiento de caché",
                        descripcion=(
                            f"La {campo} de la caché incluye github.head_ref o datos del PR "
                            f"que un atacante puede controlar. Esto puede permitir cache "
                            f"poisoning: un atacante crea un PR con un nombre de rama específico "
                            f"que colisiona con una entrada de caché legítima y la envenena."
                        ),
                        archivo=str(ruta),
                        linea=num_linea,
                        evidencia=f"{campo}: {valor[:80]}",
                        mitigacion=(
                            "Usar identificadores no controlables por el atacante en las claves "
                            "de caché: github.sha, github.run_id, o un hash del lockfile. "
                            "Evitar github.head_ref y github.event.pull_request.* en cache keys."
                        ),
                        cis="CIS Control 18.3 — Verificar la integridad del software",
                        tipo_plataforma=plataforma,
                    ))

    return hallazgos


def check_ci009_workflow_dispatch_sin_validacion(ruta: Path, datos: dict,
                                                  lineas: list[str],
                                                  plataforma: str) -> list[Hallazgo]:
    """
    CI-009 MEDIUM: Detecta workflow_dispatch con inputs de tipo string usados
    directamente en comandos run: sin validación.
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    # Verificar si tiene workflow_dispatch con inputs
    on_config = datos.get("on", datos.get(True, {}))
    if not isinstance(on_config, dict):
        return hallazgos

    dispatch_config = on_config.get("workflow_dispatch", {})
    if not dispatch_config or not isinstance(dispatch_config, dict):
        return hallazgos

    inputs = dispatch_config.get("inputs", {})
    if not isinstance(inputs, dict):
        return hallazgos

    # Recopilar nombres de inputs de tipo string (sin restricción de opciones)
    inputs_string = {
        nombre for nombre, config in inputs.items()
        if isinstance(config, dict) and
        config.get("type", "string") == "string" and
        "options" not in config  # los de tipo 'choice' tienen options
    }

    if not inputs_string:
        return hallazgos

    # Buscar si esos inputs se usan directamente en run:
    PATRON_INPUT = re.compile(
        r"\$\{\{\s*inputs\.([A-Za-z0-9_]+)\s*\}\}"
    )

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if not isinstance(run, str):
                continue

            # Buscar inputs string usados en run
            matches_encontrados = PATRON_INPUT.findall(run)
            inputs_en_run = set(matches_encontrados) & inputs_string

            if inputs_en_run:
                num_linea = obtener_linea_clave(lineas, run[:40] if len(run) > 40 else run)
                evidencia_run = run[:100] + ("..." if len(run) > 100 else "")
                hallazgos.append(Hallazgo(
                    id="CI-009",
                    severidad="MEDIUM",
                    titulo="Input de workflow_dispatch sin validación usado en run:",
                    descripcion=(
                        f"Los inputs {inputs_en_run} son de tipo string sin opciones restringidas "
                        f"y se usan directamente en un comando run:. Un operador con acceso "
                        f"workflow_dispatch podría inyectar comandos si no hay validación previa "
                        f"del input en el script."
                    ),
                    archivo=str(ruta),
                    linea=num_linea,
                    evidencia=f"run: {evidencia_run}",
                    mitigacion=(
                        "Validar y sanitizar los inputs antes de usarlos en comandos shell. "
                        "Para valores discretos, usar type: choice con options. "
                        "Asignar a variable de entorno y validar con whitelist antes de ejecutar."
                    ),
                    cis="CIS Control 18.5 — Usar análisis de código estático",
                    tipo_plataforma=plataforma,
                ))

    return hallazgos


def check_ci010_github_token_write_innecesario(ruta: Path, datos: dict,
                                                lineas: list[str],
                                                plataforma: str) -> list[Hallazgo]:
    """
    CI-010 LOW: Detecta GITHUB_TOKEN con scope write en jobs que solo hacen
    checkout + build (sin publicación, despliegue, ni creación de releases).
    """
    hallazgos: list[Hallazgo] = []

    if plataforma not in ("github_actions", "forgejo_actions"):
        return hallazgos

    # Keywords que indican que el job SÍ necesita permisos de escritura
    KEYWORDS_PUBLICACION = {
        "release", "deploy", "publish", "push", "create", "upload",
        "tag", "package", "registry", "docker push", "npm publish",
        "gh release", "gh pr", "git push",
    }

    jobs = datos.get("jobs", {})
    if not isinstance(jobs, dict):
        return hallazgos

    for nombre_job, job in jobs.items():
        if not isinstance(job, dict):
            continue

        permisos_job = job.get("permissions", {})
        if not isinstance(permisos_job, dict):
            continue

        # Solo interesa si contents tiene write
        if permisos_job.get("contents") != "write":
            continue

        # Analizar si el job parece ser solo de build/test
        steps = job.get("steps", [])
        texto_job = json.dumps(steps).lower() if isinstance(steps, list) else ""

        parece_solo_build = not any(kw in texto_job for kw in KEYWORDS_PUBLICACION)

        if parece_solo_build:
            num_linea = obtener_linea_clave(lineas, "permissions:")
            hallazgos.append(Hallazgo(
                id="CI-010",
                severidad="LOW",
                titulo=f"GITHUB_TOKEN con contents:write en job de solo build/test",
                descripcion=(
                    f"El job '{nombre_job}' tiene permissions.contents: write pero sus steps "
                    f"parecen ser solo de checkout/build/test, sin publicación ni despliegue. "
                    f"Un GITHUB_TOKEN con write podría usarse para modificar el repositorio "
                    f"si el pipeline es comprometido."
                ),
                archivo=str(ruta),
                linea=num_linea,
                evidencia=f"permissions.contents: write en job:{nombre_job}",
                mitigacion=(
                    "Cambiar a contents: read si el job no necesita modificar el repositorio. "
                    "Aplicar el principio de mínimo privilegio a todos los scopes del token."
                ),
                cis="CIS Control 6.3 — Mínimo privilegio de cuentas",
                tipo_plataforma=plataforma,
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# Motor de análisis principal
# ---------------------------------------------------------------------------

# Lista de todos los checks disponibles
TODOS_LOS_CHECKS = [
    check_ci001_secret_hardcodeado,
    check_ci002_pull_request_target,
    check_ci003_expression_injection,
    check_ci004_action_sin_pin_sha,
    check_ci005_permissions_write,
    check_ci006_self_hosted_runner,
    check_ci007_artifact_path_controlable,
    check_ci008_cache_key_controlable,
    check_ci009_workflow_dispatch_sin_validacion,
    check_ci010_github_token_write_innecesario,
]


def analizar_fichero(ruta: Path, severidad_minima: str = "LOW") -> list[Hallazgo]:
    """
    Analiza un único fichero YAML de CI/CD y devuelve la lista de hallazgos.
    Filtra por severidad mínima.
    """
    hallazgos: list[Hallazgo] = []

    # Leer contenido del fichero
    try:
        contenido = ruta.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return hallazgos

    lineas = contenido.splitlines()

    # Parsear YAML
    try:
        datos = yaml.safe_load(contenido)
    except yaml.YAMLError:
        # Fichero YAML inválido: no analizar
        return hallazgos

    if not isinstance(datos, dict):
        return hallazgos

    # Detectar plataforma
    plataforma = detectar_plataforma(ruta, datos)

    # Ejecutar todos los checks
    for check_fn in TODOS_LOS_CHECKS:
        try:
            nuevos = check_fn(ruta, datos, lineas, plataforma)
            hallazgos.extend(nuevos)
        except Exception:
            # Continuar con el siguiente check si uno falla
            pass

    # Filtrar por severidad mínima
    nivel_minimo = ORDEN_SEVERIDAD.get(severidad_minima.upper(), 1)
    hallazgos = [
        h for h in hallazgos
        if ORDEN_SEVERIDAD.get(h.severidad, 0) >= nivel_minimo
    ]

    return hallazgos


def encontrar_workflows(ruta_base: Path) -> list[Path]:
    """
    Busca todos los ficheros de workflow CI/CD en una ruta dada.
    Si es un fichero, lo devuelve directamente. Si es directorio, busca recursivamente.
    """
    ficheros: list[Path] = []

    if ruta_base.is_file():
        if ruta_base.suffix in (".yml", ".yaml"):
            ficheros.append(ruta_base)
        return ficheros

    if not ruta_base.is_dir():
        return ficheros

    # Buscar en ubicaciones conocidas de CI/CD
    patrones = [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".forgejo/workflows/*.yml",
        ".forgejo/workflows/*.yaml",
        ".gitlab-ci.yml",
        "gitlab-ci.yml",
    ]

    for patron in patrones:
        for encontrado in ruta_base.glob(patron):
            if encontrado not in ficheros:
                ficheros.append(encontrado)

    # Si no se encontró nada con los patrones específicos, buscar todos los YAML
    if not ficheros:
        for extension in ("*.yml", "*.yaml"):
            for encontrado in ruta_base.rglob(extension):
                # Excluir directorios como node_modules, .git, etc.
                partes = encontrado.parts
                excluir = False
                for parte in partes:
                    if parte in ("node_modules", ".git", "vendor", "dist", "build"):
                        excluir = True
                        break
                if not excluir and encontrado not in ficheros:
                    ficheros.append(encontrado)

    return sorted(ficheros)


# ---------------------------------------------------------------------------
# Formateo de salida
# ---------------------------------------------------------------------------

def generar_tabla_rich(hallazgos: list[Hallazgo], console: Console) -> None:
    """Muestra los hallazgos en una tabla Rich coloreada en la consola."""
    if not hallazgos:
        console.print("[bold green]✓ No se encontraron hallazgos.[/bold green]")
        return

    tabla = Table(
        title="[bold]Hallazgos de Seguridad CI/CD[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_black",
        show_lines=True,
    )

    tabla.add_column("ID", style="bold", width=8, no_wrap=True)
    tabla.add_column("Severidad", width=10, no_wrap=True)
    tabla.add_column("Archivo:Línea", style="cyan", width=40)
    tabla.add_column("Título", style="white", width=55)

    # Ordenar por severidad descendente
    hallazgos_ordenados = sorted(
        hallazgos,
        key=lambda h: ORDEN_SEVERIDAD.get(h.severidad, 0),
        reverse=True,
    )

    for h in hallazgos_ordenados:
        color = COLORES_SEVERIDAD.get(h.severidad, "white")
        sev_text = Text(h.severidad, style=color)
        archivo_corto = Path(h.archivo).name
        loc = f"{archivo_corto}:{h.linea}"
        tabla.add_row(h.id, sev_text, loc, h.titulo)

    console.print(tabla)


def generar_resumen_rich(hallazgos: list[Hallazgo], console: Console) -> None:
    """Muestra un panel de resumen con el conteo por severidad."""
    total = len(hallazgos)

    conteo: dict[str, int] = {s: 0 for s in SEVERIDADES_VALIDAS}
    for h in hallazgos:
        if h.severidad in conteo:
            conteo[h.severidad] += 1

    lineas = [f"[bold]Total hallazgos:[/bold] {total}"]
    for sev in SEVERIDADES_VALIDAS:
        if conteo[sev] > 0:
            color = COLORES_SEVERIDAD[sev]
            lineas.append(f"  [{color}]{sev}[/{color}]: {conteo[sev]}")

    if total == 0:
        resumen = "[bold green]Pipeline CI/CD analizado. No se encontraron hallazgos.[/bold green]"
    else:
        resumen = "\n".join(lineas)

    console.print(Panel(
        resumen,
        title=f"[bold]vamp-ci-audit v{HERRAMIENTA_VERSION} — Resumen[/bold]",
        border_style="bright_blue",
        padding=(1, 2),
    ))


def generar_json(hallazgos: list[Hallazgo]) -> str:
    """Serializa los hallazgos como JSON."""
    return json.dumps(
        {
            "herramienta": HERRAMIENTA_NOMBRE,
            "version": HERRAMIENTA_VERSION,
            "total_hallazgos": len(hallazgos),
            "resumen": {
                sev: sum(1 for h in hallazgos if h.severidad == sev)
                for sev in SEVERIDADES_VALIDAS
            },
            "hallazgos": [asdict(h) for h in hallazgos],
        },
        ensure_ascii=False,
        indent=2,
    )


def generar_html(hallazgos: list[Hallazgo]) -> str:
    """Genera un informe HTML básico con los hallazgos."""
    filas_html = ""
    hallazgos_ordenados = sorted(
        hallazgos,
        key=lambda h: ORDEN_SEVERIDAD.get(h.severidad, 0),
        reverse=True,
    )

    COLORES_HTML: dict[str, str] = {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ea580c",
        "MEDIUM":   "#ca8a04",
        "LOW":      "#0891b2",
    }

    for h in hallazgos_ordenados:
        color = COLORES_HTML.get(h.severidad, "#6b7280")
        archivo_corto = Path(h.archivo).name
        evidencia_esc = h.evidencia.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        filas_html += f"""
        <tr>
          <td style="font-weight:bold;white-space:nowrap">{h.id}</td>
          <td style="color:{color};font-weight:bold;white-space:nowrap">{h.severidad}</td>
          <td style="font-family:monospace;font-size:0.85em">{archivo_corto}:{h.linea}</td>
          <td style="font-weight:600">{h.titulo}</td>
          <td style="color:#6b7280;font-family:monospace;font-size:0.82em">{evidencia_esc}</td>
          <td style="font-size:0.9em">{h.mitigacion}</td>
        </tr>"""

    conteo = {s: sum(1 for h in hallazgos if h.severidad == s) for s in SEVERIDADES_VALIDAS}
    resumen_html = " | ".join(
        f'<span style="color:{COLORES_HTML[s]};font-weight:bold">{s}: {conteo[s]}</span>'
        for s in SEVERIDADES_VALIDAS
        if conteo[s] > 0
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vamp-ci-audit — Informe de Seguridad CI/CD</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
    h1 {{ color: #818cf8; margin-bottom: 0.25rem; }}
    .subtitle {{ color: #94a3b8; margin-bottom: 1.5rem; font-size: 0.9em; }}
    .resumen {{ background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem;
               margin-bottom: 1.5rem; border-left: 4px solid #818cf8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px;
             overflow: hidden; font-size: 0.9em; }}
    th {{ background: #334155; color: #94a3b8; padding: 0.75rem 1rem; text-align: left;
          font-weight: 600; text-transform: uppercase; font-size: 0.75em; letter-spacing: 0.05em; }}
    td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #334155; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #263348; }}
    .footer {{ margin-top: 2rem; color: #475569; font-size: 0.8em; text-align: center; }}
    .badge {{ display: inline-block; padding: 0.2em 0.6em; border-radius: 4px;
              font-weight: bold; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>vamp-ci-audit v{HERRAMIENTA_VERSION} — Informe de Seguridad CI/CD</h1>
  <p class="subtitle">© VampSecure Studios — VampSecure Labs Security Research Division</p>
  <div class="resumen">
    <strong>Total hallazgos: {len(hallazgos)}</strong>
    {'&nbsp;&nbsp;|&nbsp;&nbsp;' + resumen_html if resumen_html else ''}
  </div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Severidad</th>
        <th>Archivo:Línea</th>
        <th>Título</th>
        <th>Evidencia</th>
        <th>Mitigación</th>
      </tr>
    </thead>
    <tbody>
      {filas_html if filas_html else '<tr><td colspan="6" style="text-align:center;color:#22c55e">No se encontraron hallazgos</td></tr>'}
    </tbody>
  </table>
  <p class="footer">Generado por vamp-ci-audit v{HERRAMIENTA_VERSION} —
  Para Uso Exclusivo en Pruebas de Penetración Autorizadas</p>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Subcomando scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """
    Ejecuta el escaneo de un directorio o fichero de workflow.
    Devuelve el exit code: 0=sin CRITICAL/HIGH, 1=hallazgos, 2=error.
    """
    console = Console(stderr=False)

    ruta = Path(args.path)
    if not ruta.exists():
        console.print(f"[bold red]ERROR:[/bold red] La ruta '{ruta}' no existe.", highlight=False)
        return 2

    severidad_min = getattr(args, "severity", "LOW").upper()
    if severidad_min not in SEVERIDADES_VALIDAS:
        console.print(
            f"[bold red]ERROR:[/bold red] Severidad inválida '{severidad_min}'. "
            f"Opciones: {', '.join(SEVERIDADES_VALIDAS)}",
            highlight=False,
        )
        return 2

    # Localizar ficheros de workflow
    ficheros = encontrar_workflows(ruta)

    if not ficheros:
        console.print(
            f"[yellow]AVISO:[/yellow] No se encontraron ficheros de workflow CI/CD en '{ruta}'.",
            highlight=False,
        )
        return 0

    # Analizar todos los ficheros
    todos_hallazgos: list[Hallazgo] = []
    for fichero in ficheros:
        hallazgos_fichero = analizar_fichero(fichero, severidad_min)
        todos_hallazgos.extend(hallazgos_fichero)

    formato = getattr(args, "format", "table")
    salida = getattr(args, "output", None)

    # Output JSON
    if formato == "json":
        contenido_json = generar_json(todos_hallazgos)
        if salida:
            Path(salida).write_text(contenido_json, encoding="utf-8")
            console.print(f"[green]Informe JSON guardado en:[/green] {salida}", highlight=False)
        else:
            print(contenido_json)

    # Output HTML
    elif salida and salida.endswith(".html"):
        contenido_html = generar_html(todos_hallazgos)
        Path(salida).write_text(contenido_html, encoding="utf-8")
        console.print(f"[green]Informe HTML guardado en:[/green] {salida}", highlight=False)

    # Output tabla Rich (default)
    else:
        generar_tabla_rich(todos_hallazgos, console)
        generar_resumen_rich(todos_hallazgos, console)

        # Si hay --output pero no es HTML, guardar como texto JSON
        if salida:
            contenido_json = generar_json(todos_hallazgos)
            Path(salida).write_text(contenido_json, encoding="utf-8")
            console.print(f"[green]Resultados guardados en:[/green] {salida}", highlight=False)

    # Exit code
    tiene_critico_alto = any(
        h.severidad in ("CRITICAL", "HIGH") for h in todos_hallazgos
    )
    return 1 if todos_hallazgos else 0


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------

def main() -> None:
    """Punto de entrada principal de vamp-ci-audit."""
    parser = argparse.ArgumentParser(
        prog=HERRAMIENTA_NOMBRE,
        description=(
            "vamp-ci-audit — Auditor de seguridad de pipelines CI/CD\n"
            "© VampSecure Studios — VampSecure Labs Security Research Division\n"
            "Para Uso Exclusivo en Pruebas de Penetración Autorizadas"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  vamp-ci-audit scan .                        # Escanear directorio actual\n"
            "  vamp-ci-audit scan .github/workflows/        # Escanear workflows de GitHub\n"
            "  vamp-ci-audit scan workflow.yml              # Escanear fichero concreto\n"
            "  vamp-ci-audit scan . --format json           # Salida JSON\n"
            "  vamp-ci-audit scan . --output informe.html   # Informe HTML\n"
            "  vamp-ci-audit scan . --severity HIGH         # Solo HIGH y CRITICAL\n"
        ),
    )

    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {HERRAMIENTA_VERSION}",
    )

    subparsers = parser.add_subparsers(dest="subcomando", help="Subcomandos disponibles")
    subparsers.required = True

    # Subcomando scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Escanear un directorio o fichero de workflow CI/CD",
        description="Analiza ficheros de workflow en busca de vulnerabilidades de seguridad.",
    )
    parser_scan.add_argument(
        "path",
        metavar="PATH",
        help="Directorio o fichero de workflow a escanear",
    )
    parser_scan.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Formato de salida: table (default) o json",
    )
    parser_scan.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Guardar resultado en fichero (soporte .html para informe HTML)",
    )
    parser_scan.add_argument(
        "--severity",
        choices=SEVERIDADES_VALIDAS,
        default="LOW",
        metavar="NIVEL",
        help=f"Severidad mínima a reportar: {'/'.join(SEVERIDADES_VALIDAS)} (default: LOW)",
    )

    args = parser.parse_args()

    if args.subcomando == "scan":
        sys.exit(cmd_scan(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
