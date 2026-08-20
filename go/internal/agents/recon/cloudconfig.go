package recon

import (
	"sort"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// cloudConfigFieldOrder is the declaration order of the pydantic CloudConfig
// model in src/cloudsecurity_af/schemas/input.py.
//
// WHY IT IS HARD-CODED. The cloud_connector and drift_detector prompts embed
// `json.dumps(cloud_config, indent=2)`, and the key order of that JSON reaches
// the LLM verbatim. On the Python side cloud_config is produced by
// `self.input.cloud.model_dump()` (orchestrator.py), travels to the reasoner as
// a JSON object, and comes back out of `json.loads` with its DECLARATION order
// intact — pydantic dumps fields in declaration order and both json libraries
// preserve document order. In Go the reasoner receives a map[string]any, which
// has no order at all, so the order has to be restored from the model.
func cloudConfigFieldOrder() []string {
	return []string{"provider", "regions", "account_id", "assume_role_arn"}
}

// orderCloudConfig turns the unordered map a Go reasoner receives back into the
// key order Python's json.dumps would have emitted: the CloudConfig fields
// first, in declaration order, then any extra keys sorted alphabetically.
//
// Extra keys cannot occur for a CloudConfig-shaped payload (pydantic's default
// config ignores unknown input fields, so model_dump only ever emits the four),
// but sorting them keeps the output deterministic if a caller passes something
// else — Go map iteration order is randomized on purpose.
func orderCloudConfig(cloudConfig map[string]any) pyfmt.Ordered {
	// Python parity: `json.dumps(None, indent=2)` is "null", which is what a
	// nil map must render as — NOT "{}".
	if cloudConfig == nil {
		return nil
	}

	out := make(pyfmt.Ordered, 0, len(cloudConfig))
	seen := map[string]bool{}
	for _, field := range cloudConfigFieldOrder() {
		if v, ok := cloudConfig[field]; ok {
			out = append(out, pyfmt.KV{K: field, V: v})
			seen[field] = true
		}
	}
	extra := make([]string, 0)
	for k := range cloudConfig {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, pyfmt.KV{K: k, V: cloudConfig[k]})
	}
	return out
}

// cloudConfigJSON renders cloud_config the way the two harness prompts do:
// `json.dumps(cloud_config, indent=2)`.
//
// NUMBER CAVEAT: if the caller obtained the map from encoding/json without
// Decoder.UseNumber, every JSON number in it is a float64 and renders with a
// trailing ".0" where Python would print an int. CloudConfig has no numeric
// field (provider and assume_role_arn are strings, regions a list of strings,
// account_id a string), so no real payload reaches this; a caller that decodes
// with UseNumber is exact either way, because pyfmt.Dumps handles json.Number.
func cloudConfigJSON(cloudConfig map[string]any) string {
	if cloudConfig == nil {
		// Python parity: the reasoner signature types cloud_config as
		// dict[str, Any], but nothing enforces it at runtime and phases.py only
		// calls these two reasoners when cloud_config is not None. A nil map
		// still has to produce valid JSON rather than panic.
		return "null"
	}
	return pyfmt.Dumps(orderCloudConfig(cloudConfig), 2)
}
