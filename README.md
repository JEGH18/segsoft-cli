# pdgseg-cli

CLI de **SegSoft** para ejecutar el análisis de cumplimiento de seguridad desde la línea de comandos
y desde pipelines CI/CD (GitHub Actions, GitLab CI, Jenkins). Sube el proyecto al backend de SegSoft,
aplica las políticas indicadas en `.pdgseg.yml`, espera el resultado, imprime un resumen por severidad
y categoría, y termina con un **código de salida** que permite bloquear un merge cuando hay
incumplimientos críticos.

```console
$ pdgseg analyze
pdgseg 1.0.0 -> https://segsoft-icesi.westus3.cloudapp.azure.com
Políticas: Policy Set «Perfil PDG ICESI»
Comprimidos 128 archivos (0.4 MB); subiendo...
Análisis e46dde8b-… iniciado.
  RUNNING: 3/4 reglas
  COMPLETED

Resultado del análisis de SegSoft
  Cumplimiento:  75.0% (ponderado 74.8%)
  Hallazgos:     1

Hallazgos por severidad
  CRITICAL     1
  HIGH         0
  ...
  [CRITICAL] src/UserDao.java:6 - Prevención de SQL Injection con consultas parametrizadas

FALLA: hay hallazgos CRITICAL (exit code 2).
```

## Contenido

- [Instalación](#instalación)
- [Token de API](#token-de-api)
- [Uso rápido](#uso-rápido)
- [Referencia de `pdgseg analyze`](#referencia-de-pdgseg-analyze)
- [Códigos de salida](#códigos-de-salida)
- [Configuración: `.pdgseg.yml`](#configuración-pdgsegyml)
- [Integración con GitHub Actions](#integración-con-github-actions)
- [Integración con GitLab CI](#integración-con-gitlab-ci)
- [Integración con Jenkins](#integración-con-jenkins)
- [Problemas frecuentes](#problemas-frecuentes)
- [Desarrollo](#desarrollo)

## Instalación

Requiere Python 3.9 o superior. Funciona en Linux, macOS y Windows (el CI lo prueba en los tres con
Python 3.9 a 3.13).

```bash
pip install pdgseg-cli
pdgseg --version
```

La versión en desarrollo se instala desde GitHub:

```bash
pip install "git+https://github.com/JEGH18/segsoft-cli.git@main"
```

## Token de API

El CLI se autentica con un **token de API** personal (empieza por `pdgseg_`), distinto de la sesión web:

1. Entra a SegSoft y abre **Tokens de API** (ícono de llave junto a tu usuario).
2. Escribe un nombre (por ejemplo, «GitHub Actions de mi-proyecto»), elige la duración (30 días a
   1 año) y pulsa **Crear token**.
3. Copia el valor: **solo se muestra una vez**. En el servidor solo queda su hash.
4. Guárdalo como secreto del pipeline y pásalo en la variable `PDGSEG_API_TOKEN`.

El token actúa con tu usuario y tus permisos (un DEVELOPER solo ve sus propios análisis). No sirve para
crear ni revocar otros tokens. Revócalo desde la misma página si deja de usarse o se filtra: los
pipelines que lo usen dejan de autenticarse de inmediato.

## Uso rápido

```bash
cd mi-proyecto
pdgseg init                         # crea un .pdgseg.yml de ejemplo
# edita server y policySet
export PDGSEG_API_TOKEN=pdgseg_...  # en Windows (PowerShell): $env:PDGSEG_API_TOKEN = "pdgseg_..."
pdgseg analyze
echo $?                             # 0, 1, 2 o 10
```

## Referencia de `pdgseg analyze`

```
pdgseg analyze [--path DIR] [--config ARCHIVO] [--output text|json|sarif] [--output-path ARCHIVO]
               [--dry-run] [--quiet | --verbose] [--token TOKEN] [--server URL]
```

| Flag | Por defecto | Descripción |
|---|---|---|
| `--path DIR` | `.` | Directorio del proyecto a analizar. Se comprime y se sube. |
| `--config ARCHIVO` | `<path>/.pdgseg.yml` | Archivo de configuración. |
| `--output text` | sí | Resumen legible: cumplimiento, hallazgos por severidad y por categoría, políticas incumplidas y los primeros 20 hallazgos con archivo y línea. |
| `--output json` | | Un documento JSON para scripts (ver abajo). Va a la salida estándar, o a `--output-path`. |
| `--output sarif` | | Escribe un archivo [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) (para GitHub Code Scanning) y además imprime el resumen en texto. |
| `--output-path ARCHIVO` | `results.sarif` con `sarif` | Dónde escribir la salida `json` o `sarif`. Crea las carpetas que falten. |
| `--dry-run` | | Ejecuta el análisis completo pero **siempre devuelve 0** por los hallazgos, con una advertencia visible y el código que habría devuelto. Un error técnico sigue devolviendo 10. |
| `--quiet`, `-q` | | Sin mensajes de progreso ni colores. Con `--output json`, la salida estándar contiene solo el JSON. |
| `--verbose`, `-v` | | Muestra cada petición HTTP, los reintentos y el detalle de los errores inesperados. No se puede combinar con `--quiet`. |
| `--token TOKEN` | `$PDGSEG_API_TOKEN` | Token de API. Mejor por la variable: lo que va en la línea de comandos puede quedar en el historial y en los logs. |
| `--server URL` | `$PDGSEG_SERVER_URL` | URL del backend; reemplaza `server` del `.pdgseg.yml`. |

Otros comandos: `pdgseg init [--path DIR]` crea un `.pdgseg.yml` de ejemplo (no sobrescribe uno
existente); `pdgseg --version`; `pdgseg analyze --help`.

### Qué hace

1. Lee y valida `.pdgseg.yml` y resuelve las políticas (antes de subir nada: un nombre mal escrito
   falla rápido).
2. Comprime el directorio, sin `.git/`, `node_modules/`, entornos virtuales, cachés ni carpetas de
   IDE, ni lo que indique `exclude`. No sigue enlaces simbólicos. El ZIP puede pesar hasta 100 MB.
3. Lo sube, aplica la selección de políticas e inicia el análisis.
4. Consulta el estado cada `pollIntervalSeconds` hasta que termine (o lo cancela al llegar a
   `timeoutMinutes`).
5. Trae los resultados (y el SARIF, con `--output sarif`), imprime el resumen y sale con el código
   correspondiente.

La conexión siempre verifica el certificado TLS (para una CA propia, `REQUESTS_CA_BUNDLE=/ruta/ca.pem`).
Ante un fallo de red reintenta tres veces, esperando 1 s, 2 s y 4 s; una subida o un inicio de análisis
no se repiten si el servidor pudo haberlos recibido, para no duplicarlos.

### Salida JSON

```json
{
  "analysisId": "e46dde8b-…",
  "repositoryId": "f9150a8e-…",
  "status": "COMPLETED",
  "compliancePercentage": 75.0,
  "weightedCompliancePercentage": 74.8,
  "totalFindings": 1,
  "findingsBySeverity": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0 },
  "findingsByCategory": { "SQL_INJECTION": 1 },
  "policies": [{ "name": "Prevención de SQL Injection…", "status": "NON_COMPLIANT", "findings": 1 }],
  "ruleExecutionErrors": 0,
  "failOnSeverity": "high",
  "dryRun": false,
  "exitCode": 2,
  "findings": [{ "severity": "CRITICAL", "category": "SQL_INJECTION", "policyName": "…",
                 "filePath": "src/UserDao.java", "lineNumber": 6, "cweId": "CWE-89",
                 "suggestedAction": "…" }]
}
```

Con `--dry-run` se agrega `"wouldExitWith"`. Si hay un error técnico, la salida JSON es
`{"error": "mensaje", "exitCode": 10}`.

## Códigos de salida

| Resultado | Exit code |
|---|---|
| Todas las políticas COMPLIANT (sin hallazgos) | `0` |
| Solo hallazgos LOW o MEDIUM (políticas REQUIRES_REVIEW) | `0`, o `1` con `failOnSeverity: medium` |
| Al menos un hallazgo HIGH (y ningún CRITICAL) | `1`, o `0` con `failOnSeverity: critical` |
| Al menos un hallazgo CRITICAL | `2` |
| Error técnico | `10` |

`failOnSeverity` (en `.pdgseg.yml`, por defecto `high`) es la severidad mínima que hace fallar: por
debajo de ella el resultado es 0; desde ella es 1, o 2 si hay algún CRITICAL. Un hallazgo LOW nunca
hace fallar.

Son **errores técnicos (10)**: `.pdgseg.yml` inexistente o inválido, falta el token, token inválido,
vencido o revocado (401), sin permiso (403), cuenta bloqueada (423), el backend no responde después de
los reintentos, el Policy Set no existe, el proyecto supera 100 MB, el análisis falla, se cancela o no
termina a tiempo.

## Configuración: `.pdgseg.yml`

Va en la raíz del repositorio. Se valida contra el schema
[`pdgseg.schema.v1.json`](src/pdgseg/schema/pdgseg.schema.v1.json) (`schemaVersion: 1`); cualquier
campo desconocido o inválido se informa con su nombre y el CLI termina con 10.

| Campo | Obligatorio | Valores | Descripción |
|---|---|---|---|
| `schemaVersion` | sí | `1` | Versión del formato. |
| `server` | sí* | URL `https://…` | Backend de SegSoft. `http://` solo para `localhost`. *Puede venir de `PDGSEG_SERVER_URL` o `--server`. |
| `policySet` | una de las tres | nombre o id | Policy Set activo a aplicar. |
| `policies` | una de las tres | lista de ids | Políticas concretas. |
| `framework` | una de las tres | `OWASP_TOP_10_2021`, `ISO_27001`, `OWASP_ASVS`, `NIST_SP_800_53`, `DEVSECOPS`, `CUSTOM` | Todas las políticas activas del framework. |
| `failOnSeverity` | no | `medium`, `high` (defecto), `critical` | Severidad mínima que hace fallar el pipeline. |
| `exclude` | no | lista de patrones | Lo que no se sube (además de `.git/`, `node_modules/`, etc.). |
| `timeoutMinutes` | no | 1 a 120 (defecto 15) | Espera máxima del análisis. |
| `pollIntervalSeconds` | no | 2 a 60 (defecto 5) | Cada cuánto se consulta el estado. |

Patrones de `exclude` (subconjunto de `.gitignore`): `dist/` es la carpeta `dist` en cualquier nivel;
`*.min.js` compara el nombre en cualquier nivel; con `/` en medio o al inicio (`src/gen/*.py`,
`/docs`) se compara desde la raíz; `*` no cruza carpetas y `**` sí (`docs/**`, `src/**/*.py`).

### Ejemplos

Con un Policy Set (lo recomendado: lo mantiene un SECURITY_ADMIN en SegSoft):

```yaml
schemaVersion: 1
server: https://segsoft-icesi.westus3.cloudapp.azure.com
policySet: "Perfil PDG ICESI"
failOnSeverity: high
exclude: ["dist/", "target/", "src/test/"]
```

Con todas las políticas de un framework, fallando también por MEDIUM:

```yaml
schemaVersion: 1
server: https://segsoft-icesi.westus3.cloudapp.azure.com
framework: OWASP_TOP_10_2021
failOnSeverity: medium
```

Con políticas concretas y más tiempo de espera:

```yaml
schemaVersion: 1
server: https://segsoft-icesi.westus3.cloudapp.azure.com
policies:
  - cb9b2b2c-0000-0000-0000-000000000000
  - d6e19077-0000-0000-0000-000000000000
timeoutMinutes: 30
exclude: ["*.min.js", "docs/**"]
```

## Integración con GitHub Actions

`.github/workflows/security.yml`:

```yaml
name: Seguridad
on:
  pull_request:
  push:
    branches: [main]

jobs:
  segsoft:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # para subir el SARIF a Code Scanning
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pdgseg-cli
      - run: pdgseg analyze --output sarif --output-path results.sarif
        env:
          PDGSEG_API_TOKEN: ${{ secrets.PDGSEG_TOKEN }}
      - uses: github/codeql-action/upload-sarif@v4
        if: always() && hashFiles('results.sarif') != ''   # también cuando el análisis falla con 1 o 2
        with:
          sarif_file: results.sarif
          category: segsoft
```

- Crea el secreto `PDGSEG_TOKEN` en *Settings → Secrets and variables → Actions*.
- Los hallazgos aparecen como anotaciones en los archivos del PR y en *Security → Code scanning*.
  Code Scanning es gratuito en repositorios públicos; en privados requiere GitHub Advanced Security.
- Si hay un CRITICAL, el paso falla con exit code 2 y el workflow falla. Para **bloquear el merge**,
  marca el job `segsoft` como *required status check* en la protección de la rama `main`.
- Para empezar sin bloquear (mientras se corrigen los hallazgos existentes), agrega `--dry-run`.

## Integración con GitLab CI

`.gitlab-ci.yml`:

```yaml
segsoft:
  stage: test
  image: python:3.12-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - pip install pdgseg-cli
    - pdgseg analyze --output json --output-path pdgseg.json
  artifacts:
    when: always
    paths: [pdgseg.json]
```

- Define `PDGSEG_API_TOKEN` en *Settings → CI/CD → Variables*, marcada como *Masked* y *Protected*.
- Un exit code distinto de 0 hace fallar el job; con *Pipelines must succeed* en la configuración de
  merge requests, el merge queda bloqueado.
- GitLab no muestra SARIF en el merge request (sus reportes de SAST usan otro formato), así que aquí el
  resultado queda como artefacto JSON; el resumen también aparece en el log del job.

## Integración con Jenkins

```groovy
stage('SegSoft') {
    agent { docker { image 'python:3.12-slim' } }
    environment { HOME = "${env.WORKSPACE}" }
    steps {
        withCredentials([string(credentialsId: 'pdgseg-api-token', variable: 'PDGSEG_API_TOKEN')]) {
            sh 'pip install --user pdgseg-cli && python -m pdgseg.cli analyze --output sarif --output-path results.sarif'
        }
    }
    post { always { archiveArtifacts artifacts: 'results.sarif', allowEmptyArchive: true } }
}
```

La credencial `pdgseg-api-token` es de tipo *Secret text*. Un exit code distinto de 0 marca el build
como fallido.

## Problemas frecuentes

| Mensaje | Qué hacer |
|---|---|
| `Falta el token de API` | Define `PDGSEG_API_TOKEN` (en CI, como secreto) o usa `--token`. |
| `El backend rechazó el token (401): … venció o fue revocado` | Crea un token nuevo en SegSoft y actualiza el secreto. |
| `No se encontró …/.pdgseg.yml` | Crea uno con `pdgseg init` o indica otro con `--config`. |
| `No hay un Policy Set activo llamado «…»` | Revisa el nombre exacto (el mensaje sugiere parecidos) o usa su id. |
| `No se pudo conectar con … después de 4 intento(s)` | El backend no responde o no es alcanzable desde el runner. |
| `El ZIP del proyecto pesa … MB y el máximo es 100 MB` | Agrega a `exclude` builds, datos o binarios. |
| `no terminó en N minutos` | Sube `timeoutMinutes`. El análisis se cancela en el servidor. |

Con `--verbose` se ven las peticiones, los códigos HTTP y los reintentos.

## Desarrollo

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest                                            # pruebas unitarias (API simulada)
```

**Pruebas E2E** contra un SegSoft real (backend + motor + PostgreSQL), en `tests/e2e`:

```bash
export PDGSEG_E2E_SERVER_URL=http://localhost:8080
export PDGSEG_E2E_USERNAME=dev PDGSEG_E2E_PASSWORD=dev123                 # cuenta DEVELOPER
export PDGSEG_E2E_ADMIN_USERNAME=admin PDGSEG_E2E_ADMIN_PASSWORD=admin123 # opcional, para policySet
pytest -m e2e tests/e2e
```

El CI (`.github/workflows/ci.yml`) construye el paquete, prueba el wheel instalado en Linux, macOS y
Windows con Python 3.9 a 3.13, y corre los E2E levantando el backend y el motor desde `main` de sus
repositorios.

**Publicar una versión:** con el secreto `PYPI_API_TOKEN` configurado en el repositorio,

```bash
git tag v1.0.0 && git push origin v1.0.0
```

`release.yml` vuelve a correr todo el CI, comprueba que la versión del paquete coincide con el tag,
publica en PyPI con twine y crea el release de GitHub con los archivos. Lanzándolo a mano desde
*Actions* publica en TestPyPI (secreto `TEST_PYPI_API_TOKEN`) para ensayar.
