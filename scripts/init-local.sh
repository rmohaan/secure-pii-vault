#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  echo '.env already exists; preserving keys and credentials.'
  exit 0
fi
umask 077
{
  echo '# LOCAL POC ONLY. Preserve these keys for the lifetime of the database volume.'
  for name in DB_ADMIN_PASSWORD DB_APP_PASSWORD DB_MIGRATOR_PASSWORD LOCAL_WRITER_PASSWORD LOCAL_READER_PASSWORD; do
    printf '%s=%s\n' "$name" "$(openssl rand -hex 24)"
  done
  for name in LOCAL_FIELD_KEY LOCAL_ARCHIVE_KEY LOCAL_HMAC_KEY; do
    printf '%s=%s\n' "$name" "$(openssl rand -base64 32)"
  done
} > .env
echo 'Created .env (mode 600). Never commit it or use these local keys in GCP.'
