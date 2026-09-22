#!/usr/bin/env bash
#
# Builds a throwaway consumer project that installs this extension (and the PRADO framework)
# through Composer, then runs the checks in verify-extension-install.php against it.
#
#     tests/integration/run-install-test.sh [prado-path] [work-dir]
#
# Defaults: the framework at ../prado.master, a work directory under the system temp dir.
#
# A work directory the script created itself is removed when the run passes. A failing run keeps
# it so the half-built consumer can be inspected, and KEEP_WORK_DIR=1 keeps it after a passing
# run too. A work directory given as [work-dir] belongs to the caller and is never removed.
set -euo pipefail

EXTENSION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRADO_DIR="$(cd "${1:-$EXTENSION_DIR/../prado.master}" && pwd)"
PACKAGE="$(php -r 'echo json_decode(file_get_contents($argv[1]), true)["name"];' "$EXTENSION_DIR/composer.json")"

if [ -n "${2:-}" ]; then
	WORK_DIR="$2"
	WORK_DIR_IS_OURS=0
else
	WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/prado-webhooks-install.XXXXXX")"
	WORK_DIR_IS_OURS=1
fi

# Installing the consumer pulls a full vendor tree in, so leaving it behind on every run adds
# up; clean it up on the way out rather than making the caller remember to.
cleanup() {
	status=$?
	if [ "$WORK_DIR_IS_OURS" -eq 0 ]; then
		return
	fi
	if [ "$status" -eq 0 ] && [ -z "${KEEP_WORK_DIR:-}" ]; then
		rm -rf "$WORK_DIR"
	else
		echo "consumer project kept at: $WORK_DIR" >&2
	fi
}
trap cleanup EXIT

echo "extension: $EXTENSION_DIR ($PACKAGE)"
echo "framework: $PRADO_DIR"
echo "consumer:  $WORK_DIR"

mkdir -p "$WORK_DIR/protected/runtime"

# The version the path repository claims. It has to be TWebhookModule::VERSION: the verify
# script asserts the installed version matches the declared one, so a bump here without one
# there -- or the other way round -- fails the build.
cat > "$WORK_DIR/composer.json" <<JSON
{
    "name": "prado-webhooks/install-test",
    "description": "Throwaway consumer project for the Composer extension integration test.",
    "repositories": [
        { "type": "composer", "url": "https://asset-packagist.org" },
        { "type": "path", "url": "$PRADO_DIR", "options": { "versions": { "pradosoft/prado": "4.4.x-dev" } } },
        { "type": "path", "url": "$EXTENSION_DIR", "options": { "versions": { "$PACKAGE": "0.1.0" } } }
    ],
    "require": {
        "$PACKAGE": "0.1.0"
    },
    "minimum-stability": "dev",
    "prefer-stable": true
}
JSON

# The consumer requires ONLY the extension: pradosoft/prado is a requirement of the extension
# itself, so Composer must pull the framework in transitively. A path repository pins the
# framework to the LOCAL checkout under test ($PRADO_DIR) rather than resolving it from
# Packagist, so the install runs against the framework the developer is working on -- the
# repositories block is read from this root project alone, which is also why asset-packagist is
# listed here (PRADO depends on bower-asset/*).
# The module is registered by its Composer package name; its class comes from
# extra.prado.bootstrap. Its attributes and its <signature> child are what the boot check
# reads back, so this element exercises both halves of how the module is configured.
# The queue is wired up the way an application would: a data source module, a queue module
# naming it, and the webhook module naming the queue. Only a real boot resolves those ids.
cat > "$WORK_DIR/protected/application.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<application id="install-test" Mode="Normal">
  <modules>
    <module id="db" class="Prado\Data\TDataSourceConfig">
      <database ConnectionString="sqlite:$WORK_DIR/protected/runtime/webhooks.db" />
    </module>
    <module id="webhook-queue" class="Belisoful\Prado\Web\Webhooks\TDbWebhookQueue"
      ConnectionID="db" AutoCreateTable="true" />
    <module id="$PACKAGE" Timeout="5" MaxAttempts="2" QueueID="webhook-queue">
      <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature" Secret="s3cret" />
    </module>
  </modules>
</application>
XML

( cd "$WORK_DIR" && composer install --no-progress --no-interaction --quiet )

VERIFY="$EXTENSION_DIR/tests/integration/verify-extension-install.php"
echo "== composer metadata"
php "$VERIFY" capture "$WORK_DIR"
echo "== application boot"
php "$VERIFY" boot "$WORK_DIR"

echo "composer extension integration checks passed"
