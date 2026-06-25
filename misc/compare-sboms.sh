#!/bin/sh

DIRECTORY=$1
EXPECTED_NUMBER_ERRORS_OSV_SCANNER=$2
EXPECTED_NUMBER_ERRORS_TRIVY=$3
TEST_DIR=$(mktemp -d)

cargo build -r

echo "testing on ${DIRECTORY}"
echo "test dir on ${TEST_DIR}"

# 移除了所有在新版中不兼容的废弃参数
osv-scanner -r --format=cyclonedx-1-5 --output "${TEST_DIR}/osv-scanner.json" "${DIRECTORY}"
trivy fs --output "${TEST_DIR}/trivy.json" --format cyclonedx "${DIRECTORY}"
./target/release/sbom-generator --directory "${DIRECTORY}" --output "${TEST_DIR}/sbom-generator.json"

misc/compare-sbom.py "${TEST_DIR}/osv-scanner.json" "${TEST_DIR}/sbom-generator.json"
ACTUAL_NUMBER_ERRORS=$?
if [ "${ACTUAL_NUMBER_ERRORS}" != "${EXPECTED_NUMBER_ERRORS_OSV_SCANNER}" ]; then
  echo "[osv-scanner] number of errors mismatch. Expected ${EXPECTED_NUMBER_ERRORS_OSV_SCANNER}, got ${ACTUAL_NUMBER_ERRORS}"
  exit 1
fi

misc/compare-sbom.py "${TEST_DIR}/trivy.json" "${TEST_DIR}/sbom-generator.json"
ACTUAL_NUMBER_ERRORS=$?
if [ "${ACTUAL_NUMBER_ERRORS}" != "${EXPECTED_NUMBER_ERRORS_TRIVY}" ]; then
  echo "[trivy] number of errors mismatch. Expected ${EXPECTED_NUMBER_ERRORS_TRIVY}, got ${ACTUAL_NUMBER_ERRORS}"
  exit 1
fi

exit 0