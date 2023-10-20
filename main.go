package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
)

type Code struct {
	Expression   string
	Program      *vm.Program
	CompileError error
	RunError     error
	Output       interface{}
}

func (code *Code) compile(data map[string]interface{}) {
	code.Expression = strings.TrimSuffix(code.Expression, "\n")
	options := []expr.Option{
		expr.Function("uniq", uniq, new(func([]any) []any)),
		expr.Env(data),
	}
	program, err := expr.Compile(code.Expression, options...)
	if err != nil {
		code.CompileError = err
		errorCount = errorCount + 1
	} else {
		code.Program = program
	}
}

func (code *Code) run(data map[string]interface{}) {
	output, err := expr.Run(code.Program, data)
	if err != nil {
		code.RunError = err
		errorCount = errorCount + 1
	} else {
		code.Output = output
	}
}

type Value struct {
	Id         string `yaml:"id"`
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
	Code       Code
}

type Rule struct {
	Id                    string `yaml:"id"`
	Category              string `yaml:"category"`
	MessageContent        string `yaml:"message"`
	Truncate              string `yaml:"truncate"`
	AllowLongMessageValue bool
	Description           string   `yaml:"description"`
	Severity              string   `yaml:"severity"`
	Predicate             string   `yaml:"predicate"`
	Suppresses            []string `yaml:"suppresses"`
	SnippetExpressions    []string `yaml:"snippets"`
	SeverityLevel         int
	PredicateCode         Code
	SnippetCodes          []*Code
	SnippetErrorCount     int
	Collations            []string `yaml:"collate"`
}

func (rule *Rule) applyDefaults() {
	if rule.Severity == "" {
		rule.Severity = "info"
	}
	if rule.Predicate == "" {
		rule.Predicate = "true"
	}
	if rule.Truncate == "" {
		rule.Truncate = "true"
	}
}

func (rule *Rule) preCompile() {
	level, err := severityLevel(rule.Severity)
	maybeDieWithoutMessage(err)
	rule.SeverityLevel = level

	value, err := strconv.ParseBool(rule.Truncate)
	maybeDieWithoutMessage(err)
	rule.AllowLongMessageValue = !value
}

func (rule *Rule) compile(data map[string]interface{}) {

	// Compile Predicate
	rule.PredicateCode.Expression = rule.Predicate
	rule.PredicateCode.compile(data)

	// Compile Snippets
	rule.SnippetCodes = make([]*Code, len(rule.SnippetExpressions))
	for i, snippet := range rule.SnippetExpressions {
		rule.SnippetCodes[i] = &Code{Expression: snippet}
		rule.SnippetCodes[i].compile(data)
		if rule.SnippetCodes[i].CompileError != nil {
			rule.SnippetErrorCount = rule.SnippetErrorCount + 1
		}
	}
}

func (rule *Rule) runSnippets(data map[string]interface{}) {
	if len(rule.SnippetCodes) > 0 {
		for _, code := range rule.SnippetCodes {
			if code.CompileError != nil {
				code.Output = "<compile error>"
			} else {
				code.run(data)
				if code.RunError != nil {
					code.Output = "<run error>"
					//rule.SnippetErrorCount = rule.SnippetErrorCount + 1
				}
			}
		}
	}
}

func (rule *Rule) run(data map[string]interface{}) map[string]interface{} {
	collations := make(map[string]interface{})

	// Run Rule
	if rule.PredicateCode.CompileError == nil {
		output, err := expr.Run(rule.PredicateCode.Program, data)

		if err != nil {
			rule.PredicateCode.RunError = err
			errorCount = errorCount + 1
		} else {
			switch output.(type) {
			case bool:
				if output.(bool) {
					rule.runSnippets(data)
					if rule.MessageContent != "" {
						var message = rule.getMessage()
						fmt.Printf("%s: %s\n", strings.ToUpper(rule.Severity), message)
					}
					// if there are collations, then collate locally
					if rule.Collations != nil {
						for i, collation := range rule.Collations {
							collations[collation] = rule.SnippetCodes[i].Output
						}
					}
					// Suppress future rules if required
					for _, item := range rule.Suppresses {
						suppressed[item] = true
					}
				}
			default:
				rule.PredicateCode.RunError = errors.New("expression didn't result in a boolean value")
			}
		}
	}

	return collations
}

type Loop struct {
	Expression     string `yaml:"expression"`
	ExpressionCode Code
	Names          []string `yaml:"names"`
	Values         []*Value `yaml:"values"`
	Loops          []*Loop  `yaml:"loop"`
	Rules          []*Rule  `yaml:"rules"`
}

type Config struct {
	Values []*Value `yaml:"values"`
	Loops  []*Loop  `yaml:"loop"`
	Rules  []*Rule  `yaml:"rules"`
}

var errorCount int

func die(msg string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func maybeDieWithoutMessage(err error) {
	if err != nil {
		die(err.Error())
	}
}

func maybeDie(err error, msg string, args ...any) {
	if err != nil {
		die(msg, args...)
	}
}

func readData(filename string) (error, map[string]interface{}) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err, nil
	}

	var items []map[string]interface{}
	err = yaml.Unmarshal(content, &items)
	if err == nil {
		// We were given an anonymous array, so wrap it into a map with a top-level "items" key
		var result map[string]interface{}
		result = make(map[string]interface{})
		result["items"] = items
		return err, result
	} else {
		// We were given a map (hopefully)
		var result map[string]interface{}
		err = yaml.Unmarshal(content, &result)
		return err, result
	}
}

func readConfig(filename string) (error, *Config) {
	// Read the file
	content, err := os.ReadFile(filename)
	if err != nil {
		return err, nil
	}

	// Create a slice to hold the YAML data
	var config Config

	// Unmarshal the YAML data into the map
	err = yaml.Unmarshal(content, &config)
	return err, &config
}

func severityLevel(code string) (int, error) {
	switch code {
	case "test":
		return -1, nil
	case "error":
		return 0, nil
	case "warning":
		return 1, nil
	case "info":
		return 2, nil
	default:
		return -1, errors.New(fmt.Sprintf("Unable to convert %s into a severity level", code))
	}
}

func uniq(params ...any) (any, error) {
	var items []any
	items = params[0].([]any)
	result := make([]any, 0)
	for i, item := range items {
		if i == 0 {
			result = append(result, item)
		} else {
			if items[i] != result[len(result)-1] {
				result = append(result, item)
			}
		}
	}
	return result, nil
}

func processValues(data map[string]interface{}, values []*Value) {
	for _, value := range values {

		value.Code.Expression = value.Expression
		value.Code.compile(data)

		if value.Code.CompileError != nil {
			errorCount = errorCount + 1
		} else {
			value.Code.run(data)
			if value.Code.RunError != nil {
				errorCount = errorCount + 1
			} else {
				_, found := data[value.Name]
				if found {
					value.Code.RunError = errors.New("unable to save value to env because the key already exists")
				} else {
					data[value.Name] = value.Code.Output
				}
			}
		}
	}
}

var suppressed = make(map[string]bool)

func collate(collated map[string]interface{}, collations map[string]interface{}) map[string]interface{} {
	for k, v := range collations {
		if _, found := collated[k]; !found {
			collated[k] = make([]interface{}, 0)
		}
		switch v.(type) {
		case []interface{}:
			items := v.([]interface{})
			for _, item := range items {
				collated[k] = append(collated[k].([]interface{}), item)
			}
		case interface{}:
			collated[k] = append(collated[k].([]interface{}), v)
		}
	}
	return collated
}

func processRules(data map[string]interface{}, rules []*Rule, severity int) map[string]interface{} {
	collated := make(map[string]interface{}, 0)
	for _, rule := range rules {
		_, isSuppressed := suppressed[rule.Id]
		rule.applyDefaults()
		rule.preCompile()
		if rule.SeverityLevel <= severity && !isSuppressed {
			rule.compile(data)
			collations := rule.run(data)
			collated = collate(collated, collations)
		}
	}
	return collated
}

func (rule *Rule) getMessage() string {
	snippetResults := make([]interface{}, len(rule.SnippetCodes))
	for i, code := range rule.SnippetCodes {
		snippetResults[i] = code.Output
	}
	output := fmt.Sprintf(rule.MessageContent, snippetResults...)
	if len(output) > 1000 && rule.AllowLongMessageValue == false {
		output = output[0:1000] + " ... <truncated>"
	}
	return output
}

func processLoops(data map[string]interface{}, loops []*Loop, severity int) map[string]interface{} {
	collated := make(map[string]interface{}, 0)
	for _, loop := range loops {
		loop.ExpressionCode.Expression = loop.Expression
		loop.ExpressionCode.compile(data)
		if loop.ExpressionCode.CompileError != nil {
			continue
		}
		loop.ExpressionCode.run(data)
		if loop.ExpressionCode.RunError != nil {
			continue
		}
		// The expression ran, so we figure out the type (array or map) and recurse
		switch loop.ExpressionCode.Output.(type) {
		case map[interface{}]interface{}:
			for k, v := range loop.ExpressionCode.Output.(map[interface{}]interface{}) {
				d := make(map[string]interface{})
				if len(loop.Names) == 0 {
					loop.Names = []string{"key", "value"}
				}
				if len(loop.Names) == 2 {
					d["outer"] = data
					d[loop.Names[0]] = k
					d[loop.Names[1]] = v
					processValues(d, loop.Values)
					collations := processLoops(d, loop.Loops, severity)
					collated = collate(collated, collations)
					for k, v := range collations {
						if _, found := d[k]; found {
							maybeDieWithoutMessage(errors.New("oops"))
						} else {
							d[k] = v
						}
					}
					collations = processRules(d, loop.Rules, severity)
					collated = collate(collated, collations)
				} else {
					loop.ExpressionCode.RunError = errors.New("wrong number of names for map")
				}
			}
		case []interface{}:
			for _, v := range loop.ExpressionCode.Output.([]interface{}) {
				d := make(map[string]interface{})
				if len(loop.Names) == 0 {
					loop.Names = []string{"item"}
				}
				if len(loop.Names) == 1 {
					d["outer"] = data
					d[loop.Names[0]] = v
					processValues(d, loop.Values)
					collations := processLoops(d, loop.Loops, severity)
					collated = collate(collated, collations)
					for k, v := range collations {
						if _, found := d[k]; found {
							maybeDieWithoutMessage(errors.New("oops"))
						} else {
							d[k] = v
						}
					}
					collations = processRules(d, loop.Rules, severity)
					collated = collate(collated, collations)
				}
			}
		default:
			println("Oops")
		}
	}
	return collated
}

func main() {

	var rulesFile string
	flag.StringVar(&rulesFile, "rules", "rules.yaml", "validation rules")

	var dataFile string
	flag.StringVar(&dataFile, "data", "data.json", "YAML / JSON file to validate")

	var severityFlag string
	flag.StringVar(&severityFlag, "severity", "info", "severity level: info, warning, error")
	severity, _ := severityLevel(severityFlag)

	var showErrors bool
	flag.BoolVar(&showErrors, "errors", true, "show rule processing errors")

	flag.Parse()

	err, data := readData(dataFile)
	maybeDie(err, fmt.Sprintf("Unable to read data: %s", err))
	err, config := readConfig(rulesFile)

	processValues(data, config.Values)
	collations := processLoops(data, config.Loops, severity)

	for k, v := range collations {
		if _, found := data[k]; found {
			maybeDieWithoutMessage(errors.New("oops"))
		} else {
			data[k] = v
		}
	}

	processRules(data, config.Rules, severity)

	if errorCount > 0 {
		fmt.Printf("WARNING: There are %v errors\n", errorCount)
	}

	if errorCount > 0 && showErrors {
		printErrors(config)
	}
}

func reportError(format string, parameters ...interface{}) {
	if parameters == nil {
		_, _ = fmt.Fprintf(os.Stderr, format)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, format, parameters)
	}
}

func printErrors(config *Config) {
	reportError("\n")

	for _, value := range config.Values {
		if value.Code.CompileError != nil || value.Code.RunError != nil {
			reportError("Error in Value: %v\n", value.Id)
			reportError("  Predicate: %s\n", value.Expression)
			if value.Code.CompileError != nil {
				reportError("  Compile Error: %v\n", value.Code.CompileError)
			}
			if value.Code.RunError != nil {
				reportError("  Run Error: %v\n", value.Code.RunError)
			}
		}
	}

	for _, rule := range config.Rules {
		if rule.PredicateCode.CompileError != nil || rule.PredicateCode.RunError != nil || rule.SnippetErrorCount > 0 {
			reportError("Error in Rule: %v\n", rule.Id)
			if rule.PredicateCode.CompileError != nil || rule.PredicateCode.RunError != nil {
				reportError("  Predicate: %s\n", rule.Predicate)
			}
			if rule.PredicateCode.CompileError != nil {
				reportError("  Compile Error: %v\n", rule.PredicateCode.CompileError)
			}
			if rule.PredicateCode.RunError != nil {
				reportError("  Run Error: %v\n", rule.PredicateCode.RunError)
			}
			if rule.SnippetErrorCount > 0 {
				for _, snippet := range rule.SnippetCodes {
					if snippet.CompileError != nil || snippet.RunError != nil {
						reportError("  Snippet Predicate: %s\n", snippet.Expression)
						if snippet.CompileError != nil {
							reportError("    Compile Error: %v\n", snippet.CompileError)
						}
						if snippet.RunError != nil {
							reportError("    Run Error: %v\n", snippet.RunError)
						}
					}
				}

			}
		}
	}
}
