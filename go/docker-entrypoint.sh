#!/bin/sh
# Generate the opencode config at container start so the model env vars are
# honored — CLOUDSECURITY_MODEL first, then HARNESS_MODEL (see below).
#
# The Python image bakes opencode.json with a hardcoded model and a two-model
# provider whitelist, which means the model env vars are ignored by the opencode
# harness: even though the model is passed via `-m`, opencode falls back to (and
# restricts itself to) the baked model. Generating the config here from the same
# precedence chain config.py uses fixes that — the env var wins when set, and we
# fall back to the benchmarked default when it isn't.
#
# aforge (the default provider) ignores this file entirely; it is written
# unconditionally so HARNESS_PROVIDER=opencode works without a rebuild.
set -e

# Same precedence config.py:91-96 uses for harness_model, and that
# internal/config mirrors: CLOUDSECURITY_MODEL -> HARNESS_MODEL -> default.
# Reading only HARNESS_MODEL wrote an opencode.json pinned to a DIFFERENT model
# than the one the node passes to opencode with -m, which is exactly the
# whitelist mismatch this script exists to prevent. The image bakes
# HARNESS_MODEL, so without the first hop CLOUDSECURITY_MODEL could never win.
MODEL="${CLOUDSECURITY_MODEL:-${HARNESS_MODEL:-openrouter/moonshotai/kimi-k2.5}}"

# opencode keys models under a provider by the slug *without* the provider
# prefix, e.g. "openrouter/z-ai/glm-5.2" -> provider "openrouter", key "z-ai/glm-5.2".
MODEL_KEY="${MODEL#openrouter/}"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_DIR/opencode.json" <<EOF
{"\$schema":"https://opencode.ai/config.json","model":"${MODEL}","small_model":"${MODEL}","provider":{"openrouter":{"options":{"apiKey":"{env:OPENROUTER_API_KEY}"},"models":{"${MODEL_KEY}":{}}}}}
EOF

exec "$@"
