#!/bin/sh
set -eu

repository='Seokwoooo/DELETE-DENIED'
api_url="https://api.github.com/repos/$repository/releases/latest"

fail() {
    printf 'delete-denied: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Darwin ] || fail 'macOS is required'

case "$(uname -m)" in
    arm64|aarch64) target='aarch64-apple-darwin' ;;
    x86_64|amd64) target='x86_64-apple-darwin' ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/delete-denied.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

release_json="$tmp_dir/release.json"
curl -fsSL "$api_url" -o "$release_json" || fail 'could not read the latest release'
tag=$(plutil -extract tag_name raw -o - "$release_json" 2>/dev/null) || fail 'latest release has no tag'
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    || fail "latest release tag is invalid: $tag"

version=${tag#v}
asset="delete-denied-$version-$target.tar.gz"
base="https://github.com/$repository/releases/download/$tag"
archive="$tmp_dir/$asset"
checksums="$tmp_dir/SHA256SUMS"

curl -fsSL "$base/$asset" -o "$archive" || fail "could not download $asset"
curl -fsSL "$base/SHA256SUMS" -o "$checksums" || fail 'could not download SHA256SUMS'

expected=$(awk -v wanted="$asset" '
    $2 == wanted || $2 == "*" wanted { hash = $1; count++ }
    END { if (count == 1) print tolower(hash); else exit 1 }
' "$checksums") || fail "SHA256SUMS has no unique entry for $asset"
printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || fail 'release checksum is invalid'
actual=$(/usr/bin/shasum -a 256 "$archive" | awk '{print $1}')
[ "$actual" = "$expected" ] || fail 'release checksum did not match'

stage="$tmp_dir/stage"
mkdir "$stage"
tar -xzf "$archive" -C "$stage" || fail 'could not extract the release'
cli="$stage/delete-denied"
hook="$stage/delete-denied-hook"
[ -x "$cli" ] && [ -x "$hook" ] || fail 'release is missing executable files'

if "$cli" status >/dev/null 2>&1; then
    "$cli" update --trust >/dev/null
else
    "$cli" install --trust >/dev/null
fi
"$cli" doctor
