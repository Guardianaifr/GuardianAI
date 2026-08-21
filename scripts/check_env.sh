#!/bin/bash
# Check if GUARDIAN_ADMIN_PASS and REDIS_PASSWORD are set and non-empty

if [ -z "${GUARDIAN_ADMIN_PASS}" ]; then
  echo "Error: GUARDIAN_ADMIN_PASS environment variable is not set." >&2
  exit 1
fi

if [ -z "${REDIS_PASSWORD}" ]; then
  echo "Error: REDIS_PASSWORD environment variable is not set." >&2
  exit 1
fi

echo "Environment validation succeeded."
exit 0
