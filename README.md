# Actividad 3 – Seguridad en entornos cloud (IaC, contenedores y JWT)

**Alumno:** Daniel Alejandro González Salazar · **Fecha:** 9 de noviembre de 2026

Se aplicaron prácticas de seguridad en tres capas y cada control quedó validado:

| Resultado | Evidencia |
| --- | --- |
| Bucket S3 cifrado (AES-256), sin acceso público, versionado y solo HTTPS | `IsPublic: false` · [validacion_s3.txt](reportes/validacion_s3.txt) |
| Imagen Docker final con **0 vulnerabilidades** (node:14 tenía 23 críticas) | [trivy_actividad3-api_seguro.txt](reportes/trivy_actividad3-api_seguro.txt) |
| API JWT: **7/7** pruebas de autenticación/autorización | [pruebas_jwt.txt](reportes/pruebas_jwt.txt) |
| OWASP ZAP: **120 PASS, 0 FAIL, 0 WARN** | [zap_reporte.html](reportes/zap_reporte.html) |

## Índice

1. [Herramientas](#herramientas)
2. [Fase 1. Configuración segura en la nube con IaC](#fase-1-configuración-segura-en-la-nube-con-iac)
3. [Política de IAM](#política-de-iam-de-mínimo-privilegio)
4. [Fase 2. Seguridad de contenedores](#fase-2-seguridad-de-contenedores)
5. [Fase 3. Desarrollo seguro y autenticación](#fase-3-desarrollo-seguro-y-autenticación)
6. [Diagrama de arquitectura](#diagrama-de-arquitectura)
7. [Conclusiones](#conclusiones)
8. [Estructura del repositorio](#estructura-del-repositorio)
9. [Referencias](#referencias)

## Herramientas

| Herramienta | Versión | Uso |
| --- | --- | --- |
| Terraform | 1.17.1 (provider AWS 5.100.0) | IaC del bucket S3 |
| AWS CLI | 2.34.16 | Validación del bucket |
| AWS Academy Learner Lab | us-east-1 | Cuenta de laboratorio |
| Docker | 29.2.1 | Construcción de imágenes |
| Trivy | 0.76.2 | Escaneo de vulnerabilidades y configuración |
| Node.js + Express + jsonwebtoken | Node 22, Express 4.21, jsonwebtoken 9.0 | API con JWT |
| OWASP ZAP | stable (imagen Docker) | Escaneo de seguridad de la API |

---

## Fase 1. Configuración segura en la nube con IaC

El bucket **`actividad3-seguro-2024-dags`** quedó desplegado en `us-east-1` con cifrado AES-256, bloqueo de acceso público en sus 4 opciones, ACLs deshabilitadas, versionado y una política que rechaza conexiones sin HTTPS. El nombre de la guía (`actividad3-seguro-2024`) ya estaba ocupado; como los nombres de S3 son únicos en todo el mundo, se le agregaron iniciales.

### Ajustes respecto al script de la guía

- **Sintaxis actualizada.** `acl` y `server_side_encryption_configuration` dentro de `aws_s3_bucket` están obsoletos desde el provider AWS v4; se pasaron a recursos independientes ([terraform/main.tf](terraform/main.tf)).
- **Restricción del Learner Lab.** La política de la organización (SCP) de AWS Academy niega `s3:GetBucketObjectLockConfiguration`. El recurso `aws_s3_bucket` lee ese valor en los providers v4, v5 y v6, y el `apply` fallaba. Se resolvió con Terraform gestionando un stack de CloudFormation con la misma configuración ([terraform-learnerlab/main.tf](terraform-learnerlab/main.tf)).

### Script de Terraform desplegado ([terraform-learnerlab/main.tf](terraform-learnerlab/main.tf))

```hcl
# Variante para AWS Academy Learner Lab.
# El SCP del laboratorio niega s3:GetBucketObjectLockConfiguration, que el recurso
# aws_s3_bucket del provider lee siempre. Por eso Terraform gestiona el bucket mediante
# un stack de CloudFormation con la MISMA configuración segura que ../terraform/main.tf.
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "bucket_name" {
  type    = string
  default = "actividad3-seguro-2024-dags"
}

resource "aws_cloudformation_stack" "secure_bucket" {
  name = "actividad3-secure-bucket"
  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      SecureBucket = {
        Type = "AWS::S3::Bucket"
        Properties = {
          BucketName = var.bucket_name
          # Cifrado del lado del servidor AES-256 (SSE-S3)
          BucketEncryption = {
            ServerSideEncryptionConfiguration = [{
              ServerSideEncryptionByDefault = { SSEAlgorithm = "AES256" }
            }]
          }
          # Bloqueo total de acceso público
          PublicAccessBlockConfiguration = {
            BlockPublicAcls       = true
            BlockPublicPolicy     = true
            IgnorePublicAcls      = true
            RestrictPublicBuckets = true
          }
          # ACLs deshabilitadas (equivalente a acl = "private")
          OwnershipControls = {
            Rules = [{ ObjectOwnership = "BucketOwnerEnforced" }]
          }
          VersioningConfiguration = { Status = "Enabled" }
          Tags                    = [{ Key = "Proyecto", Value = "Actividad3-Seguridad" }]
        }
      }
      # Política: deniega cualquier acceso sin TLS
      SecureBucketPolicy = {
        Type = "AWS::S3::BucketPolicy"
        Properties = {
          Bucket = { Ref = "SecureBucket" }
          PolicyDocument = {
            Version = "2012-10-17"
            Statement = [{
              Sid       = "DenyInsecureTransport"
              Effect    = "Deny"
              Principal = "*"
              Action    = "s3:*"
              Resource = [
                { "Fn::GetAtt" = ["SecureBucket", "Arn"] },
                { "Fn::Join" = ["", [{ "Fn::GetAtt" = ["SecureBucket", "Arn"] }, "/*"]] }
              ]
              Condition = { Bool = { "aws:SecureTransport" = "false" } }
            }]
          }
        }
      }
    }
    Outputs = {
      BucketName = { Value = { Ref = "SecureBucket" } }
    }
  })
}

output "bucket_name" {
  value = aws_cloudformation_stack.secure_bucket.outputs["BucketName"]
}
```

<details>
<summary><b>Versión estándar para una cuenta AWS normal</b> (<a href="terraform/main.tf">terraform/main.tf</a>, extracto)</summary>

```hcl
resource "aws_s3_bucket" "secure_bucket" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_ownership_controls" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```
</details>

### Resultado de `terraform apply`

```
aws_cloudformation_stack.secure_bucket: Creation complete after 28s
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.
Outputs:
bucket_name = "actividad3-seguro-2024-dags"
```

### Validación

| Control | Comando o prueba | Resultado |
| --- | --- | --- |
| Bucket no público | `get-bucket-policy-status` | `IsPublic: false` ✅ |
| Bloqueo de acceso público | `get-public-access-block` | Las 4 opciones en `true` ✅ |
| Cifrado | `get-bucket-encryption` | `SSEAlgorithm: AES256` ✅ |
| Cifrado de objetos | `head-object` de un archivo de prueba | `ServerSideEncryption: AES256` ✅ |
| Versionado | `get-bucket-versioning` | `Enabled` ✅ |
| ACLs deshabilitadas | `get-bucket-ownership-controls` | `BucketOwnerEnforced` ✅ |
| Acceso anónimo al bucket | `curl` sin credenciales | HTTP 403 (denegado) ✅ |
| Lectura anónima de un objeto | `curl` sin credenciales | HTTP 403 (denegado) ✅ |

<details>
<summary><b>Salida completa de la validación</b></summary>

```
### aws s3api get-bucket-policy-status --bucket actividad3-seguro-2024-dags
{
    "PolicyStatus": {
        "IsPublic": false
    }
}

### aws s3api get-public-access-block --bucket actividad3-seguro-2024-dags
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}

### aws s3api get-bucket-encryption --bucket actividad3-seguro-2024-dags
{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": false,
                "BlockedEncryptionTypes": {
                    "EncryptionType": [
                        "SSE-C"
                    ]
                }
            }
        ]
    }
}

### aws s3api get-bucket-versioning --bucket actividad3-seguro-2024-dags
{
    "Status": "Enabled"
}

### aws s3api get-bucket-ownership-controls --bucket actividad3-seguro-2024-dags
{
    "OwnershipControls": {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerEnforced"
            }
        ]
    }
}

### Prueba: acceso anónimo desde Internet
HTTP 403 (403 = acceso denegado)

### Prueba: subir objeto y verificar cifrado
"AES256"

### Prueba: lectura anónima del objeto
HTTP 403
```
</details>

---

## Política de IAM de mínimo privilegio

La aplicación solo recibe `s3:GetObject` sobre los objetos de su bucket y solo por HTTPS. No puede listar, escribir, borrar ni tocar otros buckets. La política se asocia a un rol (`actividad3-app-reader`) que la aplicación asume, nunca a usuarios con llaves fijas.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadObjectsOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::actividad3-seguro-2024-dags/*",
      "Condition": {
        "Bool": { "aws:SecureTransport": "true" }
      }
    }
  ]
}
```

En [terraform/main.tf](terraform/main.tf) el rol y la política se crean con `aws_iam_role` y `aws_iam_role_policy` usando `-var create_iam_role=true`. En el Learner Lab esto queda desactivado porque el laboratorio no permite `iam:CreateRole`.

---

## Fase 2. Seguridad de contenedores

La imagen final de la API (`actividad3-api:seguro`, basada en `node:22-alpine`) tiene **0 vulnerabilidades de cualquier severidad**. La imagen obsoleta `node:14` tenía 23 críticas. Al día del escaneo, `node:18` (la que propone la guía) también está fuera de soporte desde abril de 2025 y sale peor que node:14, por eso se usó Node 22 LTS.

### Comparativa de escaneos (`trivy image`)

| Imagen | Críticas | Altas | Medias | Bajas |
| --- | ---: | ---: | ---: | ---: |
| node:14 (obsoleta) | 23 | 572 | 735 | 122 |
| node:18 (propuesta por la guía) | 228 | 2302 | 6778 | 2725 |
| node:18-alpine | 3 | 43 | 55 | 38 |
| node:22-alpine (base limpia) | 0 | 10 | 13 | 1 |
| **actividad3-api:seguro (imagen final)** | **0** | **0** | **0** | **0** |

Detalle de CVEs críticos por imagen: [trivy_resumen_comparativo.txt](reportes/trivy_resumen_comparativo.txt). Ejemplos en node:14: CVE-2024-32002 (RCE en git), CVE-2023-38408 (RCE en ssh-agent de OpenSSH), CVE-2023-45853 (desbordamiento en zlib), CVE-2021-3177 (desbordamiento de pila en Python 2.7).

### Dockerfile inseguro ([docker/inseguro/Dockerfile](docker/inseguro/Dockerfile))

```dockerfile
# Imagen base OBSOLETA (Node 14, fin de soporte abril 2023) - solo para demostrar vulnerabilidades
FROM node:14
WORKDIR /app
COPY . .
EXPOSE 3000
CMD ["node", "-e", "require('http').createServer((q,s)=>s.end('ok')).listen(3000)"]
```

### Dockerfile actualizado y endurecido ([api/Dockerfile](api/Dockerfile))

```dockerfile
# Imagen ACTUALIZADA y mínima (Alpine, Node 22 LTS) - build multi-etapa
FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-alpine
# Aplica parches de seguridad del SO y elimina npm/yarn/corepack (no se usan en runtime)
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn*
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json auth.js server.js ./
# No ejecutar como root
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/api/public || exit 1
CMD ["node", "server.js"]
```

### Mitigaciones aplicadas

1. **Base actualizada y mínima:** de Debian `node:14` a `node:22-alpine`.
2. **Build en dos etapas:** solo dependencias de producción (`npm ci --omit=dev`) llegan a la imagen final.
3. **Parches del SO:** `apk upgrade` al construir.
4. **Sin herramientas sobrantes:** se quitaron npm, yarn y corepack, origen de las 10 vulnerabilidades altas restantes.
5. **Usuario sin privilegios:** el contenedor corre como `node` (verificado con `docker exec actividad3-api whoami` → `node`).
6. **Sin secretos en la imagen:** `JWT_SECRET` por variable de entorno; `.dockerignore` excluye `.env` y `node_modules`.

### Reporte de Trivy de la imagen final

```
$ trivy image actividad3-api:seguro
┌────────────────────────────────────────────┬──────────┬─────────────────┐
│ Target                                     │   Type   │ Vulnerabilities │
├────────────────────────────────────────────┼──────────┼─────────────────┤
│ actividad3-api:seguro (alpine 3.24.4)      │  alpine  │        0        │
│ app/node_modules/express/package.json      │ node-pkg │        0        │
│ app/node_modules/jsonwebtoken/package.json │ node-pkg │        0        │
│ app/node_modules/helmet/package.json       │ node-pkg │        0        │
│ ... (resto de dependencias)                │ node-pkg │        0        │
└────────────────────────────────────────────┴──────────┴─────────────────┘
```

Reporte completo: [trivy_actividad3-api_seguro.txt](reportes/trivy_actividad3-api_seguro.txt).

`trivy config` del Dockerfile inseguro reportó 2 fallas: **DS-0002** (HIGH, corre como root) y **DS-0026** (LOW, sin HEALTHCHECK). El Dockerfile seguro: 0 fallas.

---

## Fase 3. Desarrollo seguro y autenticación

La API valida un JWT en cada endpoint sensible y el rol en `/api/admin`. Las 7 pruebas dieron el resultado esperado y OWASP ZAP terminó con **120 PASS, 0 FAIL, 0 WARN**.

### Middleware de autenticación JWT ([api/auth.js](api/auth.js))

```javascript
// Middleware de autenticación y autorización JWT
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET debe definirse por variable de entorno (mín. 32 caracteres)');
}

const VERIFY_OPTIONS = {
  algorithms: ['HS256'],      // evita ataques "alg: none" / confusión de algoritmo
  issuer: 'actividad3-api',
  audience: 'actividad3-clientes',
};

// Autenticación: valida que exista un token Bearer válido y vigente
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET, VERIFY_OPTIONS);
    return next();
  } catch (err) {
    // No se revela el motivo exacto al cliente
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// Autorización: valida que el rol del usuario esté permitido (RBAC)
function authorize(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.user || !rolesPermitidos.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permisos insuficientes' });
    }
    return next();
  };
}

function signToken(user) {
  return jwt.sign({ sub: user.username, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
    issuer: VERIFY_OPTIONS.issuer,
    audience: VERIFY_OPTIONS.audience,
  });
}

module.exports = { authenticate, authorize, signToken };
```

### Uso en los endpoints ([api/server.js](api/server.js), extracto)

```javascript
app.use(helmet());                         // cabeceras de seguridad HTTP
app.use(express.json({ limit: '10kb' }));  // limita tamaño del body

app.get('/api/public', (req, res) => res.json({ mensaje: 'Endpoint público' }));

app.get('/api/profile', authenticate, (req, res) =>
  res.json({ usuario: req.user.sub, rol: req.user.role }));

app.get('/api/admin', authenticate, authorize('admin'), (req, res) =>
  res.json({ mensaje: 'Panel de administración', usuario: req.user.sub }));
```

### Controles de desarrollo seguro

- Solo se acepta HS256: un token con `alg: none` se rechaza.
- Se validan emisor (`iss`), audiencia (`aud`) y expiración (15 minutos).
- El secreto viene de una variable de entorno (mín. 32 caracteres); la API no arranca sin él.
- Errores genéricos que no revelan por qué falló el token.
- 401 = no autenticado; 403 = autenticado sin permiso.
- Helmet, `X-Powered-By` oculto y body limitado a 10 KB.
- `npm audit`: 0 vulnerabilidades.

### Pruebas de autenticación y autorización ([api/test.js](api/test.js))

| Prueba | Esperado | Obtenido | Resultado |
| --- | :---: | :---: | :---: |
| GET /api/public sin token | 200 | 200 | ✅ PASS |
| GET /api/admin sin token | 401 | 401 | ✅ PASS |
| GET /api/admin con token firmado con otro secreto | 401 | 401 | ✅ PASS |
| GET /api/admin con token `alg=none` | 401 | 401 | ✅ PASS |
| GET /api/admin con rol user | 403 | 403 | ✅ PASS |
| GET /api/admin con rol admin | 200 | 200 | ✅ PASS |
| GET /api/profile con rol user | 200 | 200 | ✅ PASS |

### Escaneo con OWASP ZAP

Se usó `zap-api-scan.py` con una definición OpenAPI ([api/openapi.json](api/openapi.json)) de los 4 endpoints, que declara el esquema Bearer JWT. Corrió reglas pasivas y activas: inyección SQL y de comandos, path traversal, XXE, SSTI, autenticación débil, divulgación de errores, entre otras.

```
$ docker run --rm -v ./reportes:/zap/wrk ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t /zap/wrk/openapi.json -f openapi -r zap_reporte.html
...
PASS: Weak Authentication Method [10105]
PASS: Authentication Request Identified [10111]
PASS: Application Error Disclosure [90022]
PASS: Remote OS Command Injection [90020]
...
FAIL-NEW: 0  FAIL-INPROG: 0  WARN-NEW: 0  WARN-INPROG: 0  INFO: 0  IGNORE: 0  PASS: 120
```

ZAP accedió a los endpoints protegidos sin token y recibió 401 en todos: no encontró fallas de validación de tokens ni de permisos. Reporte completo: [zap_reporte.html](reportes/zap_reporte.html) · [salida completa](reportes/zap_salida.txt).

---

## Diagrama de arquitectura

Todo dato pasa por al menos dos controles antes de llegar al bucket: la API exige JWT y rol, y S3 exige un rol IAM y conexión TLS. El acceso anónimo desde Internet se rechaza con 403.

![Diagrama de arquitectura segura](diagrama/arquitectura.png)

Versión editable en draw.io: [diagrama/arquitectura-segura.drawio](diagrama/arquitectura-segura.drawio) (abrir en [app.diagrams.net](https://app.diagrams.net) → Archivo → Abrir).

---

## Conclusiones

- **IaC hace la seguridad repetible.** Cifrado, bloqueo público y solo HTTPS quedan escritos en código, no dependen de configurar la consola a mano. Las restricciones del entorno (el SCP del Learner Lab) obligan a adaptar la herramienta sin bajar los controles.
- **"Actualizar" no siempre es suficiente.** Node 18 ya llegó a fin de soporte y tenía más vulnerabilidades que Node 14. Lo que llevó la imagen a 0 fue combinar una versión LTS vigente, base mínima (Alpine), build en dos etapas y quitar herramientas que no se usan.
- **Autenticar no es autorizar.** Validar el JWT (401) y validar el rol (403) son controles distintos; las pruebas con token falsificado y `alg=none` confirman que la validación no se puede saltar.

## Estructura del repositorio

```
terraform/                 Bucket S3 seguro + rol/política IAM (cuenta AWS estándar)
terraform/iam-policy.json  Política IAM de mínimo privilegio (solo s3:GetObject)
terraform-learnerlab/      Variante desplegada en AWS Academy Learner Lab (vía CloudFormation)
docker/inseguro/           Dockerfile con imagen obsoleta (node:14)
docker/seguro/             Dockerfile actualizado y endurecido
api/                       API Express con middleware JWT, pruebas, OpenAPI y Dockerfile
diagrama/                  Diagrama de arquitectura (PNG y draw.io)
reportes/                  Trivy, OWASP ZAP, validación S3 y pruebas JWT
```

### Cómo reproducir

```bash
# Fase 1 – IaC
cd terraform-learnerlab && terraform init && terraform apply
aws s3api get-bucket-policy-status --bucket actividad3-seguro-2024-dags

# Fase 2 – Contenedores
trivy image node:14
docker build -t actividad3-api:seguro api && trivy image actividad3-api:seguro

# Fase 3 – API JWT + ZAP
docker run -d -p 3000:3000 -e JWT_SECRET="$(openssl rand -hex 32)" actividad3-api:seguro
cd api && npm install && node test.js
```

## Referencias

- AWS. (s.f.). *Nivel gratuito de AWS*. https://aws.amazon.com/es/free
- Terraform. (s.f.). *Install Terraform*. https://developer.hashicorp.com/terraform/install
- Docker. (2025). *Docker: Accelerated Container Application Development*. https://www.docker.com
- Aqua Security. (2025). *Trivy: Simple and Comprehensive Vulnerability Scanner for Containers*. https://trivy.dev
- OWASP Foundation. (2025). *ZAP: Zed Attack Proxy*. https://www.zaproxy.org
