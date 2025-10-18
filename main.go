package main

import (
    "fmt"
    "os"
    "regexp"
    "strconv"
    "strings"

    "gopkg.in/yaml.v3"
)

type ValidationError struct {
    File    string
    Line    int
    Message string
}

func (e ValidationError) Error() string {
    if e.Line > 0 {
        return fmt.Sprintf("%s:%d %s", e.File, e.Line, e.Message)
    }
    return fmt.Sprintf("%s %s", e.File, e.Message)
}

type PodConfig struct {
    APIVersion string                 `yaml:"apiVersion"`
    Kind       string                 `yaml:"kind"`
    Metadata   map[string]interface{} `yaml:"metadata"`
    Spec       map[string]interface{} `yaml:"spec"`
}

type Validator struct {
    errors []ValidationError
    file   string
}

func NewValidator(file string) *Validator {
    return &Validator{
        errors: make([]ValidationError, 0),
        file:   file,
    }
}

func (v *Validator) addError(line int, message string) {
    v.errors = append(v.errors, ValidationError{
        File:    v.file,
        Line:    line,
        Message: message,
    })
}

func (v *Validator) addRequiredError(field string) {
    v.errors = append(v.errors, ValidationError{
        File:    v.file,
        Line:    0,
        Message: fmt.Sprintf("%s is required", field),
    })
}

func (v *Validator) Validate() bool {
    return len(v.errors) == 0
}

func (v *Validator) PrintErrors() {
    for _, err := range v.errors {
        fmt.Fprintf(os.Stderr, "%s\n", err.Error())
    }
}

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintf(os.Stderr, "Usage: %s <yaml-file>\n", os.Args[0])
        os.Exit(1)
    }

    filePath := os.Args[1]
    if err := validateYAML(filePath); err != nil {
        os.Exit(1)
    }
}

func validateYAML(filePath string) error {
    content, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "%s cannot read file content: %v\n", filePath, err)
        return err
    }

    var root yaml.Node
    if err := yaml.Unmarshal(content, &root); err != nil {
        fmt.Fprintf(os.Stderr, "%s cannot unmarshal file content: %v\n", filePath, err)
        return err
    }

    validator := NewValidator(filePath)
    validateDocument(&root, validator)

    if !validator.Validate() {
        validator.PrintErrors()
        return fmt.Errorf("validation failed")
    }

    return nil
}

func validateDocument(root *yaml.Node, validator *Validator) {
    if len(root.Content) == 0 {
        validator.addRequiredError("document")
        return
    }

    doc := root.Content[0]
    validateTopLevel(doc, validator)
}

func validateTopLevel(node *yaml.Node, validator *Validator) {
    var apiVersion, kind *yaml.Node
    var metadata, spec *yaml.Node

    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "apiVersion":
                apiVersion = value
                validateAPIVersion(apiVersion, validator)
            case "kind":
                kind = value
                validateKind(kind, validator)
            case "metadata":
                metadata = value
                validateMetadata(metadata, validator)
            case "spec":
                spec = value
                validateSpec(spec, validator)
        }
    }

    if apiVersion == nil {
        validator.addRequiredError("apiVersion")
    }
    if kind == nil {
        validator.addRequiredError("kind")
    }
    if metadata == nil {
        validator.addRequiredError("metadata")
    }
    if spec == nil {
        validator.addRequiredError("spec")
    }
}

func validateAPIVersion(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "apiVersion must be string")
        return
    }

    if node.Value != "v1" {
        validator.addError(node.Line, fmt.Sprintf("apiVersion has unsupported value '%s'", node.Value))
    }
}

func validateKind(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "kind must be string")
        return
    }

    if node.Value != "Pod" {
        validator.addError(node.Line, fmt.Sprintf("kind has unsupported value '%s'", node.Value))
    }
}

func validateMetadata(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "metadata must be object")
        return
    }

    var nameFound bool
    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "name":
                nameFound = true
                validateMetadataName(value, validator)
            case "namespace":
                validateNamespace(value, validator)
            case "labels":
                validateLabels(value, validator)
        }
    }

    if !nameFound {
        validator.addError(node.Line, "name is required")
    }
}

func validateMetadataName(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "name must be string")
    }
    
    if strings.TrimSpace(node.Value) == "" {
        validator.addError(node.Line, "name is required")
    }
}

func validateNamespace(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "metadata.namespace must be string")
    }
}

func validateLabels(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "metadata.labels must be object")
        return
    }

    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        if key.Kind != yaml.ScalarNode {
            validator.addError(key.Line, "label key must be string")
        }
        if value.Kind != yaml.ScalarNode {
            validator.addError(value.Line, "label value must be string")
        }
    }
}

func validateSpec(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "spec must be object")
        return
    }

    var containersFound bool
    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
        case "os":
            validateOS(value, validator)
        case "containers":
            containersFound = true
            validateContainers(value, validator)
        }
    }

    if !containersFound {
        validator.addRequiredError("spec.containers")
    }
}

func validateOS(node *yaml.Node, validator *Validator) {
    if node.Kind == yaml.MappingNode {
        // Handle object format
        for i := 0; i < len(node.Content); i += 2 {
            if i+1 >= len(node.Content) {
                break
            }

            key := node.Content[i]
            value := node.Content[i+1]

            if key.Value == "name" {
                validateOSName(value, validator)
            }
        }
    } else if node.Kind == yaml.ScalarNode {
        // Handle string format (backward compatibility)
        validateOSName(node, validator)
    } else {
        validator.addError(node.Line, "spec.os must be object or string")
    }
}

func validateOSName(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "name must be string")
        return
    }

    if node.Value != "linux" && node.Value != "windows" {
        validator.addError(node.Line, fmt.Sprintf("os has unsupported value '%s'", node.Value))
    }
}

func validateContainers(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.SequenceNode {
        validator.addError(node.Line, "spec.containers must be array")
        return
    }

    if len(node.Content) == 0 {
        validator.addError(node.Line, "spec.containers must contain at least one container")
        return
    }

    containerNames := make(map[string]bool)
    for _, containerNode := range node.Content {
        validateContainer(containerNode, validator, containerNames)
    }
}

func validateContainer(node *yaml.Node, validator *Validator, containerNames map[string]bool) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "container must be object")
        return
    }

    var name, image *yaml.Node
    var resourcesFound bool

    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "name":
                name = value
                validateContainerName(value, validator, containerNames)
            case "image":
                image = value
                validateImage(value, validator)
            case "ports":
                validatePorts(value, validator)
            case "readinessProbe":
                validateProbe(value, validator, "readinessProbe")
            case "livenessProbe":
                validateProbe(value, validator, "livenessProbe")
            case "resources":
                resourcesFound = true
                validateResources(value, validator)
        }
    }

    if name == nil {
        validator.addError(node.Line, "name is required")
    }
    if image == nil {
        validator.addError(node.Line, "image is required")
    }
    if !resourcesFound {
        validator.addError(node.Line, "resources is required")
    }
}

func validateContainerName(node *yaml.Node, validator *Validator, containerNames map[string]bool) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "name must be string")
        return
    }

    snakeCaseRegex := regexp.MustCompile(`^[a-z]+(_[a-z]+)*$`)
    if !snakeCaseRegex.MatchString(node.Value) {
        validator.addError(node.Line, "name is required")
        return
    }

    if containerNames[node.Value] {
        validator.addError(node.Line, fmt.Sprintf("name must be unique, duplicate found: '%s'", node.Value))
    } else {
        containerNames[node.Value] = true
    }
}

func validateImage(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "image must be string")
        return
    }

    // Check domain and tag
    if !strings.HasPrefix(node.Value, "registry.bigbrother.io/") {
        validator.addError(node.Line, fmt.Sprintf("image must be in registry.bigbrother.io domain, got '%s'", node.Value))
    }

    // Check for version tag
    if !strings.Contains(node.Value, ":") {
        validator.addError(node.Line, "image must have version tag")
    } else {
        parts := strings.Split(node.Value, ":")
        if len(parts) < 2 || parts[1] == "" {
            validator.addError(node.Line, "image must have version tag")
        }
    }
}

func validatePorts(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.SequenceNode {
        validator.addError(node.Line, "ports must be array")
        return
    }

    for _, portNode := range node.Content {
        validatePort(portNode, validator)
    }
}

func validatePort(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "port must be object")
        return
    }

    var containerPortFound bool
    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "containerPort":
                containerPortFound = true
                validateContainerPort(value, validator)
            case "protocol":
                validateProtocol(value, validator)
        }
    }

    if !containerPortFound {
        validator.addRequiredError("containerPort")
    }
}

func validateContainerPort(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!int" {
        validator.addError(node.Line, "containerPort must be int")
        return
    }

    port, _ := strconv.Atoi(node.Value)

    if port <= 0 || port >= 65536 {
        validator.addError(node.Line, "containerPort value out of range")
    }
}

func validateProtocol(node *yaml.Node, validator *Validator) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "protocol must be string")
        return
    }

    if node.Value != "TCP" && node.Value != "UDP" {
        validator.addError(node.Line, fmt.Sprintf("protocol has unsupported value '%s'", node.Value))
    }
}

func validateProbe(node *yaml.Node, validator *Validator, probeType string) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, fmt.Sprintf("%s must be object", probeType))
        return
    }

    var httpGetFound bool
    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        if key.Value == "httpGet" {
            httpGetFound = true
            validateHTTPGetAction(value, validator, probeType)
        }
    }

    if !httpGetFound {
        validator.addRequiredError("httpGet")
    }
}

func validateHTTPGetAction(node *yaml.Node, validator *Validator, probeType string) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "httpGet must be object")
        return
    }

    var pathFound, portFound bool
    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "path":
                pathFound = true
                validatePath(value, validator, probeType)
            case "port":
                portFound = true
                validateProbePort(value, validator, probeType)
        }
    }

    if !pathFound {
        validator.addRequiredError("path")
    }
    if !portFound {
        validator.addRequiredError("port")
    }
}

func validatePath(node *yaml.Node, validator *Validator, probeType string) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "path must be string")
        return
    }

    if !strings.HasPrefix(node.Value, "/") {
        validator.addError(node.Line, "path must be absolute path")
    }
}

func validateProbePort(node *yaml.Node, validator *Validator, probeType string) {
    if node.Tag != "!!int" {
        validator.addError(node.Line, "port must be int")
        return
    }

    port, _ := strconv.Atoi(node.Value)

    if port <= 0 || port >= 65536 {
        validator.addError(node.Line, "port value out of range")
    }
}

func validateResources(node *yaml.Node, validator *Validator) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "resources must be object")
        return
    }

    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "requests":
                validateResourceRequirements(value, validator, "requests")
            case "limits":
                validateResourceRequirements(value, validator, "limits")
        }
    }
}

func validateResourceRequirements(node *yaml.Node, validator *Validator, reqType string) {
    if node.Kind != yaml.MappingNode {
        validator.addError(node.Line, "resources must be object")
        return
    }

    for i := 0; i < len(node.Content); i += 2 {
        if i+1 >= len(node.Content) {
            break
        }

        key := node.Content[i]
        value := node.Content[i+1]

        switch key.Value {
            case "cpu":
                validateCPU(value, validator, reqType)
            case "memory":
                validateMemory(value, validator, reqType)
        }
    }
}

func validateCPU(node *yaml.Node, validator *Validator, reqType string) {
    if node.Tag != "!!int" {
        validator.addError(node.Line, "cpu must be int")
        return
    }
    
    _, err := strconv.Atoi(node.Value)
    
    if err != nil {
        validator.addError(node.Line, "cpu must be int")
    }
}

func validateMemory(node *yaml.Node, validator *Validator, reqType string) {
    if node.Tag != "!!str" {
        validator.addError(node.Line, "memory must be string")
        return
    }

    memoryRegex := regexp.MustCompile(`^\d+(Gi|Mi|Ki)$`)
    if !memoryRegex.MatchString(node.Value) {
        validator.addError(node.Line, fmt.Sprintf("memory has invalid format '%s'", node.Value))
    }
}
