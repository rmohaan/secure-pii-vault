#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
set -a
. ./.env
set +a
exec mvn spring-boot:run -Dspring-boot.run.profiles=local
