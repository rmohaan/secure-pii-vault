# Secure investor PII vault

Runnable Java 21 / Spring Boot 3.5.16 POC with PostgreSQL 17 (Docker), application envelope encryption, KMS-backed HMAC indexes, Secret Manager integration, and a separately protected archive. No real PII is needed for the demo.

## Design decision

**AlloyDB CMEK is cluster-level, not table-level.** It protects storage and is transparent to SQL readers. This implementation stores original values, encrypted values and HMACs **inside one encrypted archive payload**; it does not persist SQL-readable plaintext. The archive uses a separate wrapping key and restricted schema. See [design](docs/design.md) for the alternative literal-plaintext design and its consequences.

## Run locally

Prerequisites: Docker Desktop running; Java 21+ and Maven 3.6.3+ for host execution. Local mode requires explicit activation and generated secrets; GCP never falls back to local keys.

```sh
./scripts/init-local.sh
docker compose up -d --wait postgres
./scripts/run-local.sh
```

Or run both service and database in Docker (no host JDK required):

```sh
./scripts/init-local.sh
docker compose --profile app up --build -d --wait
```

Application: `http://localhost:8080`; liveness: `GET /health`. The health endpoint is liveness only, not a dependency readiness probe. Data persists in the Compose volume. Preserve `.env` for the same lifetime: regenerating local keys makes existing ciphertext unreadable. Local mode is for synthetic data only; loopback HTTP and local key material are not production security.

```sh
set -a
. ./.env
set +a
curl --fail-with-body -u "writer:$LOCAL_WRITER_PASSWORD" \
  -H 'Content-Type: application/json' -X POST http://localhost:8080/investors \
  -d '{"name":"Synthetic Investor","pan":"ABCDE1234F","aadhaar":"234567890123","fatca":"Synthetic FATCA declaration"}'

curl --fail-with-body -u "writer:$LOCAL_WRITER_PASSWORD" \
  -H 'Content-Type: application/json' -X POST http://localhost:8080/investors/lookup/pan \
  -d '{"pan":"abcde1234f"}'

# Replace INVESTOR_UUID with the returned id.
curl --fail-with-body -u "writer:$LOCAL_WRITER_PASSWORD" http://localhost:8080/investors/INVESTOR_UUID
curl --fail-with-body -u "reader:$LOCAL_READER_PASSWORD" http://localhost:8080/investors/INVESTOR_UUID/pii
```

Lookup uses POST to keep the identifier out of URLs/access logs. Normal GET returns only metadata; PII requires a separate scope. Responses have Spring Security's no-store cache headers. Never enable request/response body logging in gateways, tracing, APM or this service.

| Endpoint | Required scope | Result |
|---|---|---|
| POST /investors | investors.write | 201 with generated UUID |
| POST /investors/lookup/pan | investors.read | Matching UUID or 404 |
| GET /investors/{id} | investors.read | UUID and availability flag |
| GET /investors/{id}/pii | investors.pii | Decrypted fields |

Duplicate PAN or Aadhaar returns 409. Invalid input returns 400 without echoing it. KMS/DB failures return sanitized 503. This is a single-organization POC: scopes authorize access across all investor rows. Add tenant/ownership policy before multi-tenant use.

## Test

```sh
mvn verify
```

Tests use real AES-GCM/HMAC, Spring's `MockRestServiceServer` for GCP REST contracts (no cloud credentials), and Testcontainers PostgreSQL for grants, transactions and API behavior. Integration tests are **skipped if Docker is unavailable**; check the Surefire report instead of treating a successful unit-only run as full verification. Explicit unit-only run:

```sh
mvn -Dtest=CryptographyTest,GcpGatewayTest test
```

Tests cover randomized ciphertext, tamper/AAD rejection, HMAC domain separation, checksum verification, sanitized cloud errors, round-trip storage, restricted archive access, duplicate constraints, rollback on archive failure, authorization and redacted validation errors.

## Configure GCP

Start with [.env.gcp.example](.env.gcp.example) and [deployment instructions](docs/gcp.md). GCP mode uses ADC / workload identity, a pinned Secret Manager password version, an OIDC issuer and audience, and three application KMS resources. A fourth key protects the AlloyDB cluster. Apply migrations with a distinct deployment identity; runtime Flyway is disabled in GCP. Local mode runs migrations with a separate migration login.

The project contains source/configuration only; it has not provisioned cloud resources or been validated against a real GCP project. See the production gaps and rotation procedures in the design before handling real personal data.
