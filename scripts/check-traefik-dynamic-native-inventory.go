package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type inventory struct {
	SchemaVersion int      `json:"schemaVersion"`
	Target        string   `json:"target"`
	RootType      string   `json:"rootType"`
	RootPath      string   `json:"rootPath"`
	ExposureRule  string   `json:"exposureRule"`
	Sources       []source `json:"sources"`
	ScalarTypes   []string `json:"scalarTypes"`
	NotNativePaths []negativePath `json:"notNativePaths"`
	FieldSets      []fieldSet      `json:"fieldSets"`
	Groups         []group         `json:"groups"`
}

type source struct {
	Repo    string `json:"repo"`
	Ref     string `json:"ref"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Package string `json:"package,omitempty"`
	AST     bool   `json:"ast,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}
type fieldSet struct {
	ID         string   `json:"id"`
	Prefixes   []string `json:"prefixes"`
	SourceRefs []string `json:"sourceRefs"`
	SHA256     string   `json:"sha256"`
}


type group struct {
	ID         string   `json:"id"`
	Surface    string   `json:"surface"`
	Priority   int      `json:"priority"`
	Paths      []string `json:"paths"`
	Capability string   `json:"capability"`
	DSL        string   `json:"dsl"`
	Wire       string   `json:"wire"`
	Helper     string   `json:"helper"`
	Read       string   `json:"read"`
	Acceptance string   `json:"acceptance"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Matrix     string   `json:"matrix,omitempty"`
	SourceRefs []string `json:"sourceRefs,omitempty"`
	RootType   string   `json:"rootType,omitempty"`
}
type negativePath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}


type typeDeclaration struct {
	expr    ast.Expr
	imports map[string]string
	file    string
}

type fieldSurface struct {
	fileVisible map[string]struct{}
	fileHidden  map[string]struct{}
	types       map[string]typeDeclaration
	scalars     map[string]struct{}
}

type schemaWalker struct {
	surface *fieldSurface
	active  map[string]bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Traefik dynamic inventory check:", err)
		os.Exit(1)
	}
}

func run() error {
	_, scriptPath, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("cannot locate checker source")
	}
	root := filepath.Dir(filepath.Dir(scriptPath))
	inventoryPath := filepath.Join(root, "docs", "Agents", "Spec", "Traefik-dynamic-native-inventory.json")
	matrixPath := filepath.Join(root, "docs", "Agents", "Spec", "Traefik-dynamic-native-inventory.md")

	data, err := os.ReadFile(inventoryPath)
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}
	var inv inventory
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inv); err != nil {
		return fmt.Errorf("decode inventory: %w", err)
	}
	if inv.SchemaVersion != 1 || inv.RootPath == "" || inv.RootType == "" {
		return fmt.Errorf("unsupported or incomplete inventory header")
	}

	client := &http.Client{Timeout: 25 * time.Second}
	sources, err := fetchPinnedSources(client, inv.Sources)
	if err != nil {
		return err
	}
	if err := verifyDependencyPins(inv.Sources, sources); err != nil {
		return err
	}

	surface, err := parseTypeSurface(inv, sources)
	if err != nil {
		return err
	}
	if err := verifyNegativePaths(inv.NotNativePaths, surface); err != nil {
		return err
	}
	if err := verifyGroups(inv.Groups, surface); err != nil {
		return err
	}
	if err := verifyFieldSets(inv.FieldSets, inv.Sources, inv.Groups); err != nil {
		return err
	}
	if err := verifyDelegatedSubtrees(inv.Groups, inv.Sources, root, surface); err != nil {
		return err
	}
	if err := verifyHumanMatrix(matrixPath, inv.Groups); err != nil {
		return err
	}

	fmt.Printf("pinned %d source files; classified %d file-visible and %d file-excluded native paths across %d matrix rows\n",
		len(inv.Sources), len(surface.fileVisible), len(surface.fileHidden), len(inv.Groups))
	return nil
}


func fetchPinnedSources(client *http.Client, declarations []source) (map[string][]byte, error) {
	type result struct {
		key  string
		body []byte
		err  error
	}
	results := make(chan result, len(declarations))
	limit := make(chan struct{}, 8)
	var wait sync.WaitGroup
	for _, declaration := range declarations {
		declaration := declaration
		wait.Add(1)
		go func() {
			defer wait.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			if declaration.Repo == "" || declaration.Ref == "" || declaration.Path == "" {
				results <- result{key: declaration.Path, err: fmt.Errorf("source has an empty repo/ref/path")}
				return
			}
			url := "https://raw.githubusercontent.com/" + declaration.Repo + "/" + declaration.Ref + "/" + declaration.Path
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
			if err != nil {
				results <- result{key: declaration.Path, err: err}
				return
			}
			response, err := client.Do(request)
			if err != nil {
				results <- result{key: declaration.Path, err: err}
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				results <- result{key: declaration.Path, err: fmt.Errorf("HTTP %s for %s", response.Status, declaration.Path)}
				return
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				results <- result{key: declaration.Path, err: err}
				return
			}
			digest := sha256.Sum256(body)
			actual := hex.EncodeToString(digest[:])
			if actual != declaration.SHA256 {
				results <- result{key: declaration.Path, err: fmt.Errorf("SHA-256 changed: expected %s, got %s", declaration.SHA256, actual)}
				return
			}
			results <- result{key: declaration.Path, body: body}
		}()
	}
	wait.Wait()
	close(results)

	bodies := make(map[string][]byte, len(declarations))
	var failures []string
	for item := range results {
		if item.err != nil {
			failures = append(failures, item.key+": "+item.err.Error())
			continue
		}
		bodies[item.key] = item.body
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return nil, fmt.Errorf("pinned public upstream source fetch failed: %s", strings.Join(failures, "; "))
	}
	if len(bodies) != len(declarations) {
		return nil, fmt.Errorf("fetched %d of %d pinned sources", len(bodies), len(declarations))
	}
	return bodies, nil
}

func verifyDependencyPins(declarations []source, bodies map[string][]byte) error {
	for _, declaration := range declarations {
		body := string(bodies[declaration.Path])
		switch {
		case declaration.Repo == "traefik/traefik" && declaration.Path == "go.mod":
			if !strings.Contains(body, "github.com/traefik/paerser v0.2.2") {
				return fmt.Errorf("pinned Traefik go.mod no longer requires paerser v0.2.2")
			}
		case declaration.Repo == "traefik/traefik" && declaration.Path == "pkg/config/dynamic/ext/go.mod":
			if !strings.Contains(body, "module github.com/traefik/traefik/dynamic/ext") {
				return fmt.Errorf("pinned dynamic/ext module path changed")
			}
		}
	}
	return nil
}

func parseTypeSurface(inv inventory, bodies map[string][]byte) (*fieldSurface, error) {
	surface := &fieldSurface{
		fileVisible: make(map[string]struct{}),
		fileHidden:  make(map[string]struct{}),
		types:       make(map[string]typeDeclaration),
		scalars:     make(map[string]struct{}, len(inv.ScalarTypes)),
	}
	for _, scalar := range inv.ScalarTypes {
		surface.scalars[scalar] = struct{}{}
	}
	fset := token.NewFileSet()
	for _, declaration := range inv.Sources {
		if !declaration.AST {
			continue
		}
		if declaration.Package == "" {
			return nil, fmt.Errorf("AST source %s has no package mapping", declaration.Path)
		}
		parsed, err := parser.ParseFile(fset, declaration.Path, bodies[declaration.Path], parser.AllErrors)
		if err != nil {
			return nil, fmt.Errorf("parse pinned Go source %s: %w", declaration.Path, err)
		}
		imports := make(map[string]string)
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("parse import in %s: %w", declaration.Path, err)
			}
			alias := path.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			imports[alias] = importPath
		}
		for _, declarationNode := range parsed.Decls {
			gen, ok := declarationNode.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, specNode := range gen.Specs {
				typeSpec := specNode.(*ast.TypeSpec)
				key := declaration.Package + "." + typeSpec.Name.Name
				if _, exists := surface.types[key]; exists {
					return nil, fmt.Errorf("duplicate pinned type declaration %s", key)
				}
				surface.types[key] = typeDeclaration{expr: typeSpec.Type, imports: imports, file: declaration.Path}
			}
		}
	}

	lastDot := strings.LastIndex(inv.RootType, ".")
	if lastDot < 1 || lastDot == len(inv.RootType)-1 {
		return nil, fmt.Errorf("root type must include its package path")
	}
	rootPackage, rootName := inv.RootType[:lastDot], inv.RootType[lastDot+1:]
	root, ok := surface.types[rootPackage+"."+rootName]
	if !ok {
		return nil, fmt.Errorf("root type %s is not present in pinned AST sources", inv.RootType)
	}
	walker := schemaWalker{surface: surface, active: make(map[string]bool)}
	if err := walker.walk(root.expr, rootPackage, root.imports, inv.RootPath, nil); err != nil {
		return nil, fmt.Errorf("walk root schema: %w", err)
	}
	return surface, nil
}

func (walker schemaWalker) walk(expr ast.Expr, packageName string, imports map[string]string, fieldPath string, stack []string) error {
	switch value := expr.(type) {
	case *ast.ParenExpr:
		return walker.walk(value.X, packageName, imports, fieldPath, stack)
	case *ast.StarExpr:
		return walker.walk(value.X, packageName, imports, fieldPath, stack)
	case *ast.StructType:
		for _, field := range value.Fields.List {
			if len(field.Names) == 0 {
				if err := walker.walk(field.Type, packageName, imports, fieldPath, stack); err != nil {
					return err
				}
				continue
			}
			for _, name := range field.Names {
				if !ast.IsExported(name.Name) {
					continue
				}
				tag := fieldTag(field)
				namePath := joinPath(fieldPath, nativeFieldName(name.Name, tag))
				fileTag, hasFileTag := tag.Lookup("file")
				if hasFileTag && fileTag == "-" {
					walker.surface.fileHidden[namePath] = struct{}{}
					continue
				}
				walker.surface.fileVisible[namePath] = struct{}{}
				if err := walker.walk(field.Type, packageName, imports, namePath, stack); err != nil {
					return err
				}
			}
		}
		return nil
	case *ast.MapType:
		entryPath := joinPath(fieldPath, "*")
		walker.surface.fileVisible[entryPath] = struct{}{}
		return walker.walk(value.Value, packageName, imports, entryPath, stack)
	case *ast.ArrayType:
		if isStructuredType(value.Elt, packageName, imports, walker.surface, make(map[string]bool)) {
			entryPath := joinPath(fieldPath, "*")
			walker.surface.fileVisible[entryPath] = struct{}{}
			return walker.walk(value.Elt, packageName, imports, entryPath, stack)
		}
		return nil
	case *ast.InterfaceType:
		// Any/interface payloads have no closed child type. The field path and any
		// map-key wildcard are classified, while ** rules identify the open boundary.
		return nil
	case *ast.Ident:
		if isBuiltin(value.Name) {
			return nil
		}
		return walker.walkNamed(packageName+"."+value.Name, fieldPath, stack)
	case *ast.SelectorExpr:
		alias, ok := value.X.(*ast.Ident)
		if !ok {
			return fmt.Errorf("unsupported selector at %s", fieldPath)
		}
		importPath, ok := imports[alias.Name]
		if !ok {
			return fmt.Errorf("unresolved import alias %s at %s", alias.Name, fieldPath)
		}
		key := importPath + "." + value.Sel.Name
		if _, ok := walker.surface.scalars[key]; ok {
			return nil
		}
		return walker.walkNamed(key, fieldPath, stack)
	default:
		return fmt.Errorf("unsupported Go type syntax %T at %s", expr, fieldPath)
	}
}

func (walker schemaWalker) walkNamed(key string, fieldPath string, stack []string) error {
	if walker.active[key] {
		return fmt.Errorf("recursive file type %s at %s", key, fieldPath)
	}
	declaration, ok := walker.surface.types[key]
	if !ok {
		if _, scalar := walker.surface.scalars[key]; scalar {
			return nil
		}
		return fmt.Errorf("unresolved nested type %s at %s", key, fieldPath)
	}
	for _, active := range stack {
		if active == key {
			return fmt.Errorf("recursive file type %s at %s", key, fieldPath)
		}
	}
	walker.active[key] = true
	defer delete(walker.active, key)
	return walker.walk(declaration.expr, strings.TrimSuffix(key, "."+typeName(key)), declaration.imports, fieldPath, append(stack, key))
}

func isStructuredType(expr ast.Expr, packageName string, imports map[string]string, surface *fieldSurface, active map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.ParenExpr:
		return isStructuredType(value.X, packageName, imports, surface, active)
	case *ast.StarExpr:
		return isStructuredType(value.X, packageName, imports, surface, active)
	case *ast.StructType, *ast.MapType, *ast.InterfaceType:
		return true
	case *ast.ArrayType:
		return isStructuredType(value.Elt, packageName, imports, surface, active)
	case *ast.Ident:
		if isBuiltin(value.Name) {
			return false
		}
		return isStructuredNamed(packageName+"."+value.Name, surface, active)
	case *ast.SelectorExpr:
		alias, ok := value.X.(*ast.Ident)
		if !ok {
			return false
		}
		importPath, ok := imports[alias.Name]
		if !ok {
			return false
		}
		return isStructuredNamed(importPath+"."+value.Sel.Name, surface, active)
	default:
		return false
	}
}

func isStructuredNamed(key string, surface *fieldSurface, active map[string]bool) bool {
	if _, scalar := surface.scalars[key]; scalar {
		return false
	}
	if active[key] {
		return true
	}
	declaration, ok := surface.types[key]
	if !ok {
		return false
	}
	active[key] = true
	defer delete(active, key)
	switch value := declaration.expr.(type) {
	case *ast.StructType, *ast.MapType, *ast.InterfaceType, *ast.ArrayType:
		return true
	case *ast.StarExpr:
		return isStructuredNamedExpr(value.X, key, surface, active)
	default:
		return false
	}
}

func isStructuredNamedExpr(expr ast.Expr, typeKey string, surface *fieldSurface, active map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.StructType, *ast.MapType, *ast.InterfaceType, *ast.ArrayType:
		return true
	case *ast.StarExpr:
		return isStructuredNamedExpr(value.X, typeKey, surface, active)
	case *ast.Ident:
		if isBuiltin(value.Name) {
			return false
		}
		return isStructuredNamed(strings.TrimSuffix(typeKey, "."+typeName(typeKey))+"."+value.Name, surface, active)
	default:
		return false
	}
}

func verifyNegativePaths(paths []negativePath, surface *fieldSurface) error {
	for _, item := range paths {
		if item.Path == "" || item.Reason == "" {
			return fmt.Errorf("negative native-path guard is incomplete")
		}
		for fieldPath := range surface.fileVisible {
			if pathMatches(item.Path, fieldPath) {
				return fmt.Errorf("negative native path %q appeared in pinned file surface as %q", item.Path, fieldPath)
			}
		}
		for fieldPath := range surface.fileHidden {
			if pathMatches(item.Path, fieldPath) {
				return fmt.Errorf("negative native path %q appeared in pinned file-excluded surface as %q", item.Path, fieldPath)
			}
		}
	}
	return nil
}

func verifyFieldSets(fieldSets []fieldSet, sources []source, groups []group) error {
	if len(fieldSets) == 0 {
		return fmt.Errorf("inventory has no pinned field sets")
	}
	sourceByPath := make(map[string]source, len(sources))
	for _, item := range sources {
		sourceByPath[item.Path] = item
	}
	ids := make(map[string]struct{}, len(fieldSets))
	for _, item := range fieldSets {
		if item.ID == "" || item.SHA256 == "" || len(item.Prefixes) == 0 || len(item.SourceRefs) == 0 {
			return fmt.Errorf("field set is incomplete")
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate field set id %s", item.ID)
		}
		ids[item.ID] = struct{}{}
		for _, sourcePath := range item.SourceRefs {
			if _, ok := sourceByPath[sourcePath]; !ok {
				return fmt.Errorf("field set %s references unpinned source %s", item.ID, sourcePath)
			}
		}
		actual := fieldSetDigest(item, sourceByPath)
		if actual != item.SHA256 {
			return fmt.Errorf("field set %s digest changed: expected %s, got %s", item.ID, item.SHA256, actual)
		}
	}

	for _, item := range groups {
		for _, groupPath := range item.Paths {
			bestSpecificity := -1
			best := 0
			for _, fieldSet := range fieldSets {
				for _, prefix := range fieldSet.Prefixes {
					if !pathMatches(prefix, groupPath) {
						continue
					}
					specificity := pathSpecificity(prefix)
					if specificity > bestSpecificity {
						bestSpecificity = specificity
						best = 1
					} else if specificity == bestSpecificity {
						best++
					}
				}
			}
			if best == 0 {
				return fmt.Errorf("group %s path %q has no pinned type-field set", item.ID, groupPath)
			}
			if best != 1 {
				return fmt.Errorf("group %s path %q matches ambiguous type-field sets", item.ID, groupPath)
			}
		}
	}
	return nil
}

func fieldSetDigest(item fieldSet, sources map[string]source) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, "traefik-native-field-set-v1\n"+item.ID+"\n")
	prefixes := append([]string(nil), item.Prefixes...)
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		_, _ = io.WriteString(digest, "prefix\t"+prefix+"\n")
	}
	sourceRefs := append([]string(nil), item.SourceRefs...)
	sort.Strings(sourceRefs)
	for _, sourcePath := range sourceRefs {
		_, _ = io.WriteString(digest, "source\t"+sourcePath+"\t"+sources[sourcePath].SHA256+"\n")
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func pathSpecificity(pattern string) int {
	specificity := 0
	for _, segment := range strings.Split(pattern, ".") {
		if segment != "*" && segment != "**" {
			specificity++
		}
	}
	return specificity
}

func verifyGroups(groups []group, surface *fieldSurface) error {
	if len(groups) == 0 {
		return fmt.Errorf("inventory has no classification groups")
	}
	ids := make(map[string]struct{}, len(groups))
	patterns := make(map[string]int)
	for _, item := range groups {
		if item.ID == "" || item.Capability == "" || item.DSL == "" || item.Wire == "" || item.Helper == "" || item.Read == "" || item.Acceptance == "" || item.Status == "" || item.Reason == "" {
			return fmt.Errorf("matrix group has an empty required column")
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate group id %s", item.ID)
		}
		ids[item.ID] = struct{}{}
		if item.Surface != "file" && item.Surface != "file-excluded" && item.Surface != "delegated" {
			return fmt.Errorf("group %s has invalid surface %q", item.ID, item.Surface)
		}
		if item.Surface == "delegated" && (item.Matrix == "" || len(item.SourceRefs) == 0) {
			return fmt.Errorf("delegated group %s must name a matrix and pinned source references", item.ID)
		}
		for _, pattern := range item.Paths {
			if pattern == "" {
				return fmt.Errorf("group %s has an empty path pattern", item.ID)
			}
			patterns[item.ID+"\x00"+pattern]++
		}
	}

	for _, item := range groups {
		if item.Surface == "delegated" {
			continue
		}
		for _, pattern := range item.Paths {
			count := 0
			for fieldPath := range selectedSurface(item.Surface, surface) {
				if pathMatches(pattern, fieldPath) {
					count++
				}
			}
			if count == 0 {
				return fmt.Errorf("group %s path %q matches no pinned %s fields", item.ID, pattern, item.Surface)
			}
		}
	}

	if err := classifyEvery("file", surface.fileVisible, groups); err != nil {
		return err
	}
	if err := classifyEvery("file-excluded", surface.fileHidden, groups); err != nil {
		return err
	}
	return nil
}

func selectedSurface(name string, surface *fieldSurface) map[string]struct{} {
	if name == "file" {
		return surface.fileVisible
	}
	return surface.fileHidden
}

func classifyEvery(surfaceName string, fields map[string]struct{}, groups []group) error {
	if len(fields) == 0 {
		return fmt.Errorf("pinned source has no %s fields", surfaceName)
	}
	for fieldPath := range fields {
		bestPriority := -int(^uint(0)>>1) - 1
		best := 0
		var winner string
		for _, item := range groups {
			if item.Surface != surfaceName || !matchesAny(item.Paths, fieldPath) {
				continue
			}
			if item.Priority > bestPriority {
				bestPriority = item.Priority
				best = 1
				winner = item.ID
			} else if item.Priority == bestPriority {
				best++
			}
		}
		if best == 0 {
			return fmt.Errorf("unclassified %s native path %q", surfaceName, fieldPath)
		}
		if best != 1 {
			return fmt.Errorf("ambiguous highest-priority classification for %s path %q", surfaceName, fieldPath)
		}
		_ = winner
	}
	return nil
}

func verifyDelegatedSubtrees(groups []group, sources []source, root string, surface *fieldSurface) error {
	pinned := make(map[string]struct{}, len(sources))
	for _, item := range sources {
		pinned[item.Path] = struct{}{}
	}
	for _, item := range groups {
		if item.Surface != "delegated" {
			continue
		}
		matrixPath := filepath.Join(root, "docs", "Agents", "Spec", item.Matrix)
		if _, err := os.Stat(matrixPath); err != nil {
			return fmt.Errorf("delegated group %s matrix %s is unavailable: %w", item.ID, item.Matrix, err)
		}
		if item.RootType != "" {
			if _, ok := surface.types[item.RootType]; !ok {
				return fmt.Errorf("delegated group %s root type %s is not in pinned sources", item.ID, item.RootType)
			}
		}
		for _, sourcePath := range item.SourceRefs {
			if _, ok := pinned[sourcePath]; !ok {
				return fmt.Errorf("delegated group %s references unpinned source %s", item.ID, sourcePath)
			}
		}
	}
	return nil
}

func verifyHumanMatrix(matrixPath string, groups []group) error {
	data, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("read six-column matrix: %w", err)
	}
	rows := make(map[string]string)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) != 6 {
			return fmt.Errorf("matrix line %d has %d columns, expected six", lineNumber+1, len(cells))
		}
		firstCell := strings.Fields(strings.TrimSpace(cells[0]))
		if len(firstCell) == 0 {
			continue
		}
		id := strings.Trim(firstCell[0], "`")
		if strings.EqualFold(id, "capability") || strings.EqualFold(id, "id") || strings.Trim(id, "-:") == "" {
			continue
		}
		if _, exists := rows[id]; exists {
			return fmt.Errorf("matrix repeats group %s", id)
		}
		rows[id] = line
	}
	for _, item := range groups {
		row, ok := rows[item.ID]
		if !ok {
			return fmt.Errorf("matrix has no six-column row for group %s", item.ID)
		}
		for _, pattern := range item.Paths {
			if !strings.Contains(row, pattern) {
				return fmt.Errorf("matrix row %s omits path pattern %q", item.ID, pattern)
			}
		}
		if item.Matrix != "" && !strings.Contains(row, item.Matrix) {
			return fmt.Errorf("matrix row %s omits delegated matrix %s", item.ID, item.Matrix)
		}
	}
	if len(rows) != len(groups) {
		return fmt.Errorf("matrix has %d rows for %d inventory groups", len(rows), len(groups))
	}
	return nil
}

func matchesAny(patterns []string, fieldPath string) bool {
	for _, pattern := range patterns {
		if pathMatches(pattern, fieldPath) {
			return true
		}
	}
	return false
}

func pathMatches(pattern, fieldPath string) bool {
	return matchSegments(strings.Split(pattern, "."), strings.Split(fieldPath, "."))
}

func matchSegments(pattern, value []string) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	if pattern[0] == "**" {
		if len(pattern) == 1 {
			return true
		}
		for offset := 0; offset <= len(value); offset++ {
			if matchSegments(pattern[1:], value[offset:]) {
				return true
			}
		}
		return false
	}
	if len(value) == 0 {
		return false
	}
	if pattern[0] != "*" && pattern[0] != value[0] {
		return false
	}
	return matchSegments(pattern[1:], value[1:])
}

func fieldTag(field *ast.Field) reflect.StructTag {
	if field.Tag == nil {
		return ""
	}
	value, err := strconv.Unquote(field.Tag.Value)
	if err != nil {
		return ""
	}
	return reflect.StructTag(value)
}

func nativeFieldName(goName string, tag reflect.StructTag) string {
	if value, ok := tag.Lookup("json"); ok {
		name := strings.SplitN(value, ",", 2)[0]
		if name != "" && name != "-" {
			return name
		}
	}
	runes := []rune(goName)
	if len(runes) == 0 {
		return goName
	}
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func isBuiltin(name string) bool {
	switch name {
	case "any", "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
		return true
	default:
		return false
	}
}

func typeName(key string) string {
	index := strings.LastIndex(key, ".")
	if index < 0 {
		return key
	}
	return key[index+1:]
}

