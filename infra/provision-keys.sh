#!/bin/sh
# Review before running. Creates resources and IAM bindings in a real GCP project.
set -eu
: "${PROJECT_ID:?Set project}"
: "${REGION:?Set region}"
: "${RUNTIME_SERVICE_ACCOUNT:?Set full service account email}"
: "${DB_PASSWORD_SECRET_ID:?Set existing database password secret id}"
KEY_RING=${KEY_RING:-investors}
ROTATION_DAYS=${ROTATION_DAYS:-90}
case "$ROTATION_DAYS" in
  ''|*[!0-9]*) echo 'ROTATION_DAYS must be a positive whole number' >&2; exit 1 ;;
esac
if [ "$ROTATION_DAYS" -lt 1 ]; then
  echo 'ROTATION_DAYS must be at least 1' >&2
  exit 1
fi
gcloud kms keyrings create "$KEY_RING" --project="$PROJECT_ID" --location="$REGION"
for key in field-kek archive-kek alloydb-cmek; do
  gcloud kms keys create "$key" --project="$PROJECT_ID" --location="$REGION" --keyring="$KEY_RING" --purpose=encryption --rotation-period="${ROTATION_DAYS}d"
 done
# Cloud KMS automatically creates a new encryption-key version every 90 days.
# HMAC index rotation is deliberately not configured here: a new HMAC version
# changes every stored lookup value and therefore needs the controlled migration
# documented in docs/design.md.
gcloud kms keys create blind-index --project="$PROJECT_ID" --location="$REGION" --keyring="$KEY_RING" --purpose=mac --default-algorithm=hmac-sha256
gcloud kms keys add-iam-policy-binding field-kek --project="$PROJECT_ID" --location="$REGION" --keyring="$KEY_RING" --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud kms keys add-iam-policy-binding archive-kek --project="$PROJECT_ID" --location="$REGION" --keyring="$KEY_RING" --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" --role=roles/cloudkms.cryptoKeyEncrypter
gcloud kms keys add-iam-policy-binding blind-index --project="$PROJECT_ID" --location="$REGION" --keyring="$KEY_RING" --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" --role=roles/cloudkms.signerVerifier
gcloud secrets add-iam-policy-binding "$DB_PASSWORD_SECRET_ID" --project="$PROJECT_ID" --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" --role=roles/secretmanager.secretAccessor
# For stricter IAM, replace signerVerifier with a custom role containing only cloudkms.cryptoKeyVersions.useToSign.
# Grant the AlloyDB service agent encrypter/decrypter on alloydb-cmek separately, per docs/gcp.md.
# Do not grant the runtime service account any role on alloydb-cmek or archive decrypt.
