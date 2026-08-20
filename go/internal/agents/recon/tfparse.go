package recon

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// This file ports src/cloudsecurity_af/agents/recon/_terraform_parser.py.
//
// Python parses every *.tf with `pyhcl2` and writes an inventory.json; Go uses
// hashicorp/hcl/v2 + hclsyntax (the canonical Terraform parser) instead. The
// FILE FORMAT — key sets, key order, resource ids, provider mapping, reference
// extraction, reverse references — is reproduced exactly. The one place the two
// cannot agree is how a NON-CONSTANT expression is rendered; see the
// "EXPRESSION RENDERING" note on exprToValue for the full divergence report.

// _REF_PATTERN in Python.
//
// Go's regexp implements the same leftmost-first search as Python's `re` for a
// pattern without alternation backtracking, and RE2 supports \b (ASCII word
// boundary). Python's \b is Unicode-aware; since every character class here is
// ASCII, the two differ only when a matched run is adjacent to a non-ASCII word
// character — no Terraform identifier can be.
var refPattern = regexp.MustCompile(`\b((?:data\.)?[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\b`)

// nonRefPrefixes is _NON_REF_PREFIXES in Python: HCL namespaces that look like
// a resource reference but are not one.
var nonRefPrefixes = []string{"var.", "local.", "each.", "self.", "count.", "path.", "terraform."}

// providerMap is _PROVIDER_MAP in Python: Terraform type prefix -> provider
// family. Order is irrelevant (it is a pure lookup).
var providerMap = map[string]string{
	"aws":        "aws",
	"azurerm":    "azure",
	"azuread":    "azure",
	"google":     "gcp",
	"kubernetes": "kubernetes",
	"helm":       "kubernetes",
	"oci":        "oci",
	"alicloud":   "alicloud",
}

// providerFromType ports _provider_from_type.
//
//	prefix = resource_type.split("_")[0] if "_" in resource_type else resource_type
//	return _PROVIDER_MAP.get(prefix, prefix)
func providerFromType(resourceType string) string {
	prefix := resourceType
	if i := strings.Index(resourceType, "_"); i >= 0 {
		prefix = resourceType[:i]
	}
	if mapped, ok := providerMap[prefix]; ok {
		return mapped
	}
	return prefix
}

// extractReferences ports _extract_references: every resource-looking token in
// any string anywhere in the config, de-duplicated and sorted.
func extractReferences(config any) []string {
	refs := map[string]struct{}{}
	walkForRefs(config, refs)
	out := make([]string, 0, len(refs))
	for r := range refs {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// walkForRefs ports _walk_for_refs.
func walkForRefs(obj any, refs map[string]struct{}) {
	switch x := obj.(type) {
	case string:
		for _, m := range refPattern.FindAllStringSubmatch(x, -1) {
			candidate := m[1]
			skip := false
			for _, p := range nonRefPrefixes {
				if strings.HasPrefix(candidate, p) {
					skip = true
					break
				}
			}
			if !skip {
				refs[candidate] = struct{}{}
			}
		}
	case pyfmt.Ordered:
		for _, kv := range x {
			walkForRefs(kv.V, refs)
		}
	case []any:
		for _, item := range x {
			walkForRefs(item, refs)
		}
	}
	// Python parity: ints, floats, bools and None contribute nothing, and no
	// other type can appear in the value model.
}

// sanitize ports _sanitize: keep str/int/float/bool/None and containers as they
// are, stringify anything else.
//
// The Go value model only ever contains those kinds already (json.Number
// included — it is the stand-in for an arbitrary-precision Python int), so this
// is an identity walk in practice; it is ported so a future value kind cannot
// leak an unserializable object into inventory.json.
func sanitize(obj any) any {
	switch x := obj.(type) {
	case pyfmt.Ordered:
		out := make(pyfmt.Ordered, len(x))
		for i, kv := range x {
			out[i] = pyfmt.KV{K: kv.K, V: sanitize(kv.V)}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = sanitize(item)
		}
		return out
	case string, int, int64, float64, bool, nil:
		return x
	case json.Number:
		// The stand-in for a Python int too large for Go's int (ctyToValue).
		// Python's _sanitize keeps it because `isinstance(obj, int)` is true
		// whatever its magnitude.
		return x
	}
	return pyfmt.Str(obj)
}

// ---------------------------------------------------------------------------
// HCL AST -> value model
// ---------------------------------------------------------------------------

// exprToValue ports _expr_to_value.
//
// PYTHON SHAPE (preserved exactly):
//
//	Literal          -> the Python value
//	ObjectExpression -> dict, recursing per field
//	ArrayExpression  -> list, recursing per element
//	anything else    -> a STRING
//
// EXPRESSION RENDERING — THE ONE DELIBERATE DIVERGENCE IN THIS PORT.
// Python's "anything else" branch ends in `str(expr)`, which for pyhcl2 is the
// dataclass repr of the AST node, byte offsets and all. Running the Python
// parser over tests/fixtures/vulnerable_infra/main.tf produces, for
// `iam_instance_profile = aws_iam_instance_profile.web_profile.name`:
//
//	"GetAttr(span=SourceSpan(start=219, end=260, source_id=SourceId(value=1)),
//	 on=GetAttr(span=SourceSpan(start=219, end=255, ...), ...)"
//
// i.e. a serialization of the parser's internal node graph, keyed to absolute
// byte offsets in the source file. That is not information any consumer wants
// (the harness prompts, the graph builder and the hunters all read `config` as
// if it held Terraform), and reproducing it in Go would mean re-implementing
// pyhcl2's repr including its span arithmetic.
//
// This port therefore renders a non-constant expression as its SOURCE TEXT —
// `aws_iam_instance_profile.web_profile.name` — which is what the design
// contract (§3, "anything non-constant → its source text") directs. Consequences,
// all of them documented and asserted in tfparse_test.go:
//
//   - `config` values for non-constant attributes read as Terraform rather than
//     as pyhcl2 reprs.
//   - `references` (and therefore `referenced_by`, and therefore the graph's
//     edges) are computed over that text, so the Go port finds the REAL
//     references that Python's repr text accidentally hides, and does not find
//     the spurious ones the repr text accidentally creates. On the fixture,
//     Python reports references ["t2.micro"] for aws_instance.web_server (from
//     the *literal* "t2.micro") and misses the two real ones; Go reports
//     ["aws_iam_instance_profile.web_profile", "aws_security_group.allow_all"].
//   - Constant expressions are unaffected: strings, numbers, bools, lists and
//     objects of constants evaluate to the same values in both.
//
// Two smaller, unrelated divergences fall out of the same branch, both of them
// Go producing the sane value where Python produces a repr string:
//
//   - `null` -> Go JSON null, Python "Null(span=SourceSpan(...))".
//   - a negated literal such as `-1` -> Go -1, Python
//     "UnaryExpression(span=..., op=UnaryOperator(..., type='-'), ...)".
func exprToValue(expr hclsyntax.Expression, src []byte) any {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		// Python: ObjectExpression -> {key: _expr_to_value(v)}
		out := make(pyfmt.Ordered, 0, len(e.Items))
		for _, item := range e.Items {
			key := objectKey(item.KeyExpr, src)
			val := exprToValue(item.ValueExpr, src)
			replaced := false
			for i := range out {
				if out[i].K == key {
					out[i].V = val
					replaced = true
					break
				}
			}
			if !replaced {
				out = append(out, pyfmt.KV{K: key, V: val})
			}
		}
		return out

	case *hclsyntax.TupleConsExpr:
		// Python: ArrayExpression -> [_expr_to_value(v) for v in values]
		out := make([]any, 0, len(e.Exprs))
		for _, sub := range e.Exprs {
			out = append(out, exprToValue(sub, src))
		}
		return out

	case *hclsyntax.TemplateExpr:
		// A quoted string or a heredoc. pyhcl2 represents every one of them —
		// plain, escaped or interpolated — as a String literal whose `_raw` is
		// the UNINTERPRETED text between the delimiters, which is what
		// templateText returns. Verified against the interpreter:
		//
		//	nl    = "a\nb"          -> "a\\nb"   (the escape is NOT processed)
		//	quote = "a\"b"          -> "a\\\"b"
		//	mixed = "x${var.y}\nz"  -> "x${var.y}\\nz"
		//
		// so evaluating the literal would be WRONG here even though it is the
		// semantically nicer value.
		return templateText(e, src)

	case *hclsyntax.TemplateWrapExpr:
		// `"${expr}"` with nothing around it.
		return templateText(e, src)
	}

	// Everything else: evaluate it if it is constant, otherwise fall back to
	// source text (see the divergence note above).
	if v, diags := expr.Value(nil); !diags.HasErrors() {
		return ctyToValue(v, expr, src)
	}
	return sourceText(expr, src)
}

// objectKey ports the key half of Python's ObjectExpression branch:
//
//	key_str = getattr(k, "name", None) or getattr(getattr(k, "value", k), "_raw", str(k))
//	d[str(key_str)] = ...
//
// i.e. a bare identifier key contributes its name and a quoted key its text.
func objectKey(keyExpr hclsyntax.Expression, src []byte) string {
	if kw := hcl.ExprAsKeyword(keyExpr); kw != "" {
		return kw
	}
	inner := keyExpr
	if k, ok := keyExpr.(*hclsyntax.ObjectConsKeyExpr); ok {
		inner = k.Wrapped
	}
	// A quoted key is a template, and pyhcl2 takes its `_raw` — the
	// uninterpreted text between the quotes — exactly as it does for a quoted
	// VALUE. Going through templateText keeps keys and values consistent.
	if t, ok := inner.(*hclsyntax.TemplateExpr); ok {
		return templateText(t, src)
	}
	if v, diags := inner.Value(nil); !diags.HasErrors() && v.Type() == cty.String && !v.IsNull() {
		return v.AsString()
	}
	return sourceText(inner, src)
}

// ctyToValue converts an evaluated cty value into the port's value model.
//
// Number handling reproduces Python's int/float split: pyhcl2 yields an `int`
// for an integer literal and a `float` for one written with a decimal point,
// and json.dump renders those as `2` and `2.0` respectively. (pyhcl2 REJECTS
// exponent notation outright — see ParseTerraformDirectory's note on
// parser-acceptance divergence.) cty keeps only a big.Float, so the LITERAL
// TEXT decides: a mathematically integral value written without `.`/`e` is an
// int, everything else a float.
//
// A Python int is ARBITRARY PRECISION and json.dump writes its exact digits, so
// an integer literal beyond Go's `int` is carried as a json.Number holding the
// literal rather than degraded to a float64. Verified against the repo venv on
// a one-file fixture: `big_port = 12345678901234567890` writes exactly
// `12345678901234567890` into inventory.json in Python; returning
// `bf.Float64()` here wrote `1.2345678901234567e+19`, which then propagated
// into graph.json's `config_summary` (the substring "port" is a
// configSummaryKeywords match) and into the hunter prompt's `Config: {...}`
// line. pyfmt.Dumps re-emits an integral json.Number verbatim, and
// pyfmt.Load reads it back as one, so the value survives the whole
// inventory.json -> graph.json -> prompt chain.
// For a COMPOUND constant expression (`true ? 1 : 2`, `1 + 2`) the whole
// expression's text is what gets inspected, which is the right answer for every
// such expression Terraform actually contains — Python does not fold those at
// all, it stringifies them, so they are already on the documented divergence
// list.
func ctyToValue(v cty.Value, expr hclsyntax.Expression, src []byte) any {
	if v.IsNull() {
		return nil
	}
	if !v.IsKnown() {
		return sourceText(expr, src)
	}
	t := v.Type()
	switch {
	case t == cty.Bool:
		return v.True()
	case t == cty.String:
		return v.AsString()
	case t == cty.Number:
		bf := v.AsBigFloat()
		if bf.IsInt() && !strings.ContainsAny(sourceText(expr, src), ".eE") {
			// acc == big.Exact, plus a range check so a value beyond `int` on a
			// 32-bit build does not wrap.
			if i, acc := bf.Int64(); acc == 0 && int64(int(i)) == i {
				return int(i)
			}
			// Out of `int` range: keep Python's arbitrary-precision digits.
			if bi, acc := bf.Int(nil); acc == big.Exact {
				return json.Number(bi.String())
			}
		}
		f, _ := bf.Float64()
		return f
	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		out := []any{}
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			out = append(out, ctyToValue(ev, expr, src))
		}
		return out
	case t.IsObjectType(), t.IsMapType():
		// Only reachable for a value produced by evaluating a non-Object AST
		// node (an ObjectConsExpr is destructured above and keeps source
		// order). cty has no insertion order, so keys are SORTED here —
		// deterministic, and documented.
		keys := make([]string, 0)
		vals := map[string]cty.Value{}
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			if k.Type() != cty.String || k.IsNull() {
				continue
			}
			keys = append(keys, k.AsString())
			vals[k.AsString()] = ev
		}
		sort.Strings(keys)
		out := make(pyfmt.Ordered, 0, len(keys))
		for _, k := range keys {
			out = append(out, pyfmt.KV{K: k, V: ctyToValue(vals[k], expr, src)})
		}
		return out
	}
	return sourceText(expr, src)
}

// sourceText returns the exact bytes expr occupies in the file.
func sourceText(expr hclsyntax.Expression, src []byte) string {
	return rangeText(expr.Range(), src)
}

func rangeText(rng hcl.Range, src []byte) string {
	start, end := rng.Start.Byte, rng.End.Byte
	if start < 0 || end > len(src) || start > end {
		return ""
	}
	return string(src[start:end])
}

// templateText returns a template expression's raw inner text, which is what
// pyhcl2 stores as a String literal's `_raw`: the characters between the
// delimiters, uninterpreted.
//
//   - `"..."`      -> the text between the quotes, escapes left alone.
//   - `<<EOT ...`  -> the heredoc body, flush-dedented for the `<<-` flavor and
//     with its final newline removed, matching pyhcl2 exactly.
//   - anything else (which should not occur) -> the source text unchanged.
func templateText(expr hclsyntax.Expression, src []byte) string {
	raw := sourceText(expr, src)
	if body, ok := heredocBody(raw); ok {
		return body
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}
	return raw
}

// heredocHeader matches a heredoc introducer: `<<EOT\n` or `<<-EOT\n`.
var heredocHeader = regexp.MustCompile(`^<<(-?)([A-Za-z_][A-Za-z0-9_]*)\r?\n`)

// heredocBody extracts the body of a heredoc from its raw source, reproducing
// pyhcl2's `_raw` for one: the text between the introducer line and the closing
// marker line, flush-dedented when the `<<-` flavor asked for it, minus the
// final newline.
//
// The dedent rule is pyhcl2's, not HCL's — see flushDedent. Applying it to the
// RAW text rather than to the parsed literal parts is what keeps an
// interpolated heredoc intact: HCL evaluates `${...}` away, pyhcl2 does not,
// and neither does this.
func heredocBody(raw string) (string, bool) {
	m := heredocHeader.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	flush, delim := m[1] == "-", m[2]

	body := raw[len(m[0]):]
	lines := strings.SplitAfter(body, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimRight(strings.TrimLeft(lines[i], " \t"), "\r\n")
		if trimmed == delim {
			body = strings.Join(lines[:i], "")
			break
		}
	}

	if flush {
		body = flushDedent(body)
	}
	return strings.TrimSuffix(body, "\n"), true
}

// flushDedent implements pyhcl2's `<<-` rule, which is NOT HCL's.
//
// Verified against the interpreter on four shapes:
//
//	"    a\n      \n    b"   -> "a\n  \nb"        (whitespace-only line trimmed too)
//	"    a\n\n    b"          -> unchanged          (an EMPTY line makes the min 0)
//	"\t\ta\n\t\t\tb"          -> unchanged          (tabs are not counted)
//	"    a\n     b"           -> "a\n b"
//
// so the rule is: minimum number of leading SPACE characters over EVERY body
// line (the closing-marker line excluded, empty lines included as zero), then
// that many characters removed from every line. HCL instead skips blank lines
// and counts any unicode space, which is why this cannot delegate to
// hclsyntax's own flush handling.
func flushDedent(body string) string {
	lines := strings.SplitAfter(body, "\n")
	// SplitAfter leaves a trailing "" when body ends with a newline; that is
	// not a line and must not drag the minimum down to zero.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	if len(lines) == 0 {
		return body
	}

	minSpaces := -1
	for _, ln := range lines {
		n := 0
		for n < len(ln) && ln[n] == ' ' {
			n++
		}
		if minSpaces < 0 || n < minSpaces {
			minSpaces = n
		}
	}
	if minSpaces <= 0 {
		return body
	}

	var b strings.Builder
	for _, ln := range lines {
		b.WriteString(ln[minSpaces:])
	}
	return b.String()
}

// blockToDict ports _block_to_dict: a block body becomes {attributes..., nested
// blocks...}.
//
// Python reads pyhcl2's `block.attributes` dict (insertion-ordered by source
// position) and then its `block.blocks` list. hclsyntax stores attributes in an
// unordered map, so they are re-sorted by source offset to recover the same
// order; blocks are already in source order.
func blockToDict(body *hclsyntax.Body, src []byte) pyfmt.Ordered {
	result := pyfmt.Ordered{}
	if body == nil {
		return result
	}

	attrs := make([]*hclsyntax.Attribute, 0, len(body.Attributes))
	for _, a := range body.Attributes {
		attrs = append(attrs, a)
	}
	sort.Slice(attrs, func(i, j int) bool {
		return attrs[i].SrcRange.Start.Byte < attrs[j].SrcRange.Start.Byte
	})
	for _, a := range attrs {
		result = setOrdered(result, a.Name, exprToValue(a.Expr, src))
	}

	for _, sub := range body.Blocks {
		subName := sub.Type
		subDict := blockToDict(sub.Body, src)
		if len(sub.Labels) > 0 {
			label := sub.Labels[0]
			// Python: result.setdefault(sub_name, {})[label] = sub_dict
			if existing, ok := result.Get(subName); ok {
				if nested, isMap := existing.(pyfmt.Ordered); isMap {
					result = setOrdered(result, subName, setOrdered(nested, label, subDict))
					continue
				}
				// Python parity DIVERGENCE: Python raises TypeError here (it
				// would subscript a non-dict), which aborts the whole parse and
				// sends run_iac_reader down its harness fallback. Go replaces
				// the value instead, so one pathological file cannot cost the
				// deterministic path for an entire repository.
			}
			result = setOrdered(result, subName, pyfmt.Ordered{{K: label, V: subDict}})
			continue
		}
		// Unlabeled: first one is a dict, repeats collapse into a list.
		if existing, ok := result.Get(subName); ok {
			if list, isList := existing.([]any); isList {
				result = setOrdered(result, subName, append(list, subDict))
			} else {
				result = setOrdered(result, subName, []any{existing, subDict})
			}
			continue
		}
		result = setOrdered(result, subName, subDict)
	}

	return result
}

// setOrdered assigns key in Python dict order: an existing key keeps its
// position, a new key is appended.
func setOrdered(o pyfmt.Ordered, key string, val any) pyfmt.Ordered {
	for i := range o {
		if o[i].K == key {
			o[i].V = val
			return o
		}
	}
	return append(o, pyfmt.KV{K: key, V: val})
}

// ---------------------------------------------------------------------------
// Directory walk
// ---------------------------------------------------------------------------

// terraformFiles reproduces `sorted(Path(repo_path).rglob("*.tf"))`.
//
// Two pathlib details matter and are reproduced:
//   - rglob does NOT skip dot-directories, so `.terraform/**` is included
//     (verified against Python 3.11 on this machine).
//   - PurePath ordering compares path COMPONENTS, not the raw string, so
//     "a-b/c.tf" sorts after "a/b.tf" even though the raw strings sort the
//     other way.
//
// pathlib's recursive selector also refuses to descend into symlinked
// directories, which filepath.WalkDir does for free (it never follows them).
func terraformFiles(repoPath string) ([]string, error) {
	// Python parity: rglob on a missing path — or on a path that is a FILE —
	// yields nothing rather than raising (verified on Python 3.11).
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return nil, nil
	}
	var rels []string
	err := filepath.WalkDir(repoPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Python parity: rglob silently skips directories it cannot read.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".tf") {
			return nil
		}
		rel, relErr := filepath.Rel(repoPath, p)
		if relErr != nil {
			return nil
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rels, func(i, j int) bool { return lessPathParts(rels[i], rels[j]) })
	return rels, nil
}

// lessPathParts compares two slash-separated relative paths component-wise,
// which is what pathlib.PurePath.__lt__ does.
func lessPathParts(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

// ---------------------------------------------------------------------------
// parse_terraform_directory
// ---------------------------------------------------------------------------

// ParseTerraformDirectory ports parse_terraform_directory: parse every *.tf
// under repoPath and write inventory.json into outputDir.
//
// Returns (inventoryPath, totalResources, iacType) — the Python tuple — plus an
// error for the failures Python raises on (the makedirs / open / write path).
// Python parity: a .tf file that fails to parse is SKIPPED, not fatal
// (`except Exception: continue`).
//
// DIVERGENCE (documented) — WHICH FILES FAIL. The skip rule is identical on
// both sides, but the two parsers do not agree on which files trigger it, and
// the unit of divergence is the WHOLE FILE: every resource, variable, output,
// provider and module declared in it is present in one inventory and absent
// from the other, which propagates to graph.json, to the hunters' RELEVANT
// RESOURCES / RELEVANT RELATIONSHIPS / INVENTORY STATS blocks and to the chain
// parent prompt's {{RESOURCE_GRAPH_JSON}}. It runs in BOTH directions; both
// were measured against pyhcl2 in the repo venv and hclsyntax here:
//
//   - SCIENTIFIC NOTATION. `p = 1e3`, `1E3` and `1.5e-3` are valid HCL native
//     syntax and hclsyntax parses them; pyhcl2 raises DiagnosticError, so
//     Python drops the entire file. Go emits the resources, Python emits none.
//   - A NEWLINE INSIDE A TERNARY. An expression whose `?` is followed by a
//     line break parses in pyhcl2 and is an "Invalid expression" diagnostic
//     for hclsyntax, so the divergence reverses: Python keeps the file, Go
//     drops it.
//
// Go has the better behaviour in the first case and the worse one in the
// second, and neither is worth reproducing — the point of recording it is that
// a reviewer diffing the two nodes' inventories on a real repository can tell
// this apart from a bug.
func ParseTerraformDirectory(repoPath, outputDir string) (string, int, string, error) {
	tfFiles, err := terraformFiles(repoPath)
	if err != nil {
		return "", 0, "", fmt.Errorf("cloudsecurity recon: walking %s: %w", repoPath, err)
	}

	resources := []any{}
	variables := []any{}
	outputs := []any{}
	providers := []any{}
	modules := []any{}

	for _, rel := range tfFiles {
		src, readErr := os.ReadFile(filepath.Join(repoPath, filepath.FromSlash(rel)))
		if readErr != nil {
			continue // Python: `except Exception: continue`
		}
		file, diags := hclsyntax.ParseConfig(src, rel, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() || file == nil {
			continue
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}

		for _, block := range body.Blocks {
			labels := block.Labels
			cfg := blockToDict(block.Body, src)

			switch {
			case block.Type == "resource" && len(labels) >= 2:
				rtype, name := labels[0], labels[1]
				resources = append(resources, pyfmt.Ordered{
					{K: "id", V: rtype + "." + name},
					{K: "type", V: rtype},
					{K: "name", V: name},
					{K: "provider", V: providerFromType(rtype)},
					{K: "file_path", V: rel},
					{K: "line_number", V: 0},
					{K: "config", V: sanitize(cfg)},
					{K: "references", V: toAnySlice(extractReferences(cfg))},
					{K: "referenced_by", V: []any{}},
				})

			case block.Type == "data" && len(labels) >= 2:
				dtype, name := labels[0], labels[1]
				resources = append(resources, pyfmt.Ordered{
					{K: "id", V: "data." + dtype + "." + name},
					{K: "type", V: "data." + dtype},
					{K: "name", V: name},
					{K: "provider", V: providerFromType(dtype)},
					{K: "file_path", V: rel},
					{K: "line_number", V: 0},
					{K: "config", V: sanitize(cfg)},
					{K: "references", V: toAnySlice(extractReferences(cfg))},
					{K: "referenced_by", V: []any{}},
				})

			case block.Type == "variable" && len(labels) >= 1:
				variables = append(variables, pyfmt.Ordered{
					{K: "name", V: labels[0]},
					// Python: str(vcfg.get("type", "")) if vcfg.get("type") is not None else None
					{K: "type", V: strOrNil(cfg, "type")},
					{K: "default", V: strOrNil(cfg, "default")},
					// Python parity: description is NOT str()-ed.
					{K: "description", V: getOrNil(cfg, "description")},
					{K: "file_path", V: rel},
				})

			case block.Type == "output" && len(labels) >= 1:
				// Python: str(ocfg.get("value", "")) — no None guard, so a
				// missing `value` becomes the empty STRING, not null.
				val, ok := cfg.Get("value")
				if !ok {
					val = ""
				}
				outputs = append(outputs, pyfmt.Ordered{
					{K: "name", V: labels[0]},
					{K: "value", V: pyfmt.Str(val)},
					{K: "description", V: getOrNil(cfg, "description")},
					{K: "file_path", V: rel},
				})

			case block.Type == "provider" && len(labels) >= 1:
				providers = append(providers, pyfmt.Ordered{
					{K: "name", V: labels[0]},
					{K: "region", V: getOrNil(cfg, "region")},
					{K: "alias", V: getOrNil(cfg, "alias")},
					// Python parity: always None — the parser never reads a
					// version constraint out of a provider block.
					{K: "version", V: nil},
				})

			case block.Type == "module" && len(labels) >= 1:
				modSource, ok := cfg.Get("source")
				if !ok {
					modSource = ""
				}
				modules = append(modules, pyfmt.Ordered{
					{K: "name", V: labels[0]},
					{K: "source", V: pyfmt.Str(modSource)},
					{K: "version", V: getOrNil(cfg, "version")},
					{K: "file_path", V: rel},
				})
			}
		}
	}

	// Reverse references: for every resource, who points at it.
	refTargets := map[string][]string{}
	for _, r := range resources {
		res := r.(pyfmt.Ordered)
		id, _ := res.Get("id")
		idStr, _ := id.(string)
		refs, _ := res.Get("references")
		for _, ref := range refs.([]any) {
			refStr, _ := ref.(string)
			refTargets[refStr] = append(refTargets[refStr], idStr)
		}
	}
	// Python parity: `r["referenced_by"] = ...` overwrites an existing key, so
	// the field keeps its declared position in the resource dict.
	for _, r := range resources {
		res := r.(pyfmt.Ordered)
		id, _ := res.Get("id")
		idStr, _ := id.(string)
		setOrdered(res, "referenced_by", toAnySlice(refTargets[idStr]))
	}

	inventory := pyfmt.Ordered{
		{K: "resources", V: resources},
		{K: "variables", V: variables},
		{K: "outputs", V: outputs},
		{K: "providers", V: providers},
		{K: "modules", V: modules},
	}

	if err := os.MkdirAll(outputDir, 0o777); err != nil {
		return "", 0, "", fmt.Errorf("cloudsecurity recon: creating %s: %w", outputDir, err)
	}
	inventoryPath := filepath.Join(outputDir, "inventory.json")
	if err := os.WriteFile(inventoryPath, []byte(pyfmt.Dumps(inventory, 2)), 0o666); err != nil {
		return "", 0, "", fmt.Errorf("cloudsecurity recon: writing %s: %w", inventoryPath, err)
	}

	return inventoryPath, len(resources), "terraform", nil
}

// strOrNil is Python's `str(cfg.get(k, "")) if cfg.get(k) is not None else None`.
func strOrNil(cfg pyfmt.Ordered, key string) any {
	v, ok := cfg.Get(key)
	if !ok || v == nil {
		return nil
	}
	return pyfmt.Str(v)
}

// getOrNil is Python's `cfg.get(k)` — the raw value, or None when absent.
func getOrNil(cfg pyfmt.Ordered, key string) any {
	v, ok := cfg.Get(key)
	if !ok {
		return nil
	}
	return v
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
