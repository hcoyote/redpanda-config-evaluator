package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

type Code struct {
	Expression   string
	Program      *vm.Program
	CompileError error
	RunError     error
	Output       interface{}
}

type Printable interface {
	Message() string
	Snippets() []*Code
	AllowLongMessage() bool
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

type Output struct {
	Id                 int    `yaml:"id"`
	MessageContent     string `yaml:"message"`
	Severity           string `yaml:"severity"`
	SeverityLevel      int
	SnippetExpressions []string `yaml:"snippets"`
	SnippetCodes       []*Code
	SnippetErrorCount  int
}

func (o Output) Message() string {
	return o.MessageContent
}

func (o Output) Snippets() []*Code {
	return o.SnippetCodes
}

func (o Output) AllowLongMessage() bool {
	return true
}

type Value struct {
	Id         int    `yaml:"id"`
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
	Code       Code
}

type Rule struct {
	Id                    int      `yaml:"id"`
	Category              string   `yaml:"category"`
	MessageContent        string   `yaml:"message"`
	AllowLongMessageValue bool     `yaml:"allow-long-message"`
	Description           string   `yaml:"description"`
	Severity              string   `yaml:"severity"`
	Expression            string   `yaml:"expression"`
	Suppresses            []int    `yaml:"suppresses"`
	SnippetExpressions    []string `yaml:"snippets"`
	SeverityLevel         int
	Code                  Code
	SnippetCodes          []*Code
	SnippetErrorCount     int
}

func (r Rule) Message() string {
	return r.MessageContent
}

func (r Rule) Snippets() []*Code {
	return r.SnippetCodes
}

func (r Rule) AllowLongMessage() bool {
	return r.AllowLongMessageValue
}

type Loop struct {
	Expression string   `yaml:"expression"`
	Names      []string `yaml:"names"`
	Code       Code
	Values     []*Value  `yaml:"values"`
	Outputs    []*Output `yaml:"outputs"`
	Rules      []*Rule   `yaml:"rules"`
	Loops      []*Loop   `yaml:"loop"`
}

type Config struct {
	Values  []*Value  `yaml:"values"`
	Outputs []*Output `yaml:"outputs"`
	Rules   []*Rule   `yaml:"rules"`
	Loops   []*Loop   `yaml:"loop"`
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
			//value, err := expr.Run(program, data)
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

func processOutputs(data map[string]interface{}, outputs []*Output, severity int) {
	for _, output := range outputs {

		if output.Severity == "" {
			output.Severity = "info"
		}
		level, err := severityLevel(output.Severity)
		maybeDieWithoutMessage(err)
		output.SeverityLevel = level
		if output.SeverityLevel <= severity {

			// Compile Snippets
			output.SnippetCodes = make([]*Code, len(output.SnippetExpressions))
			for i, snippet := range output.SnippetExpressions {
				output.SnippetCodes[i] = &Code{Expression: snippet}
				output.SnippetCodes[i].compile(data)
				if output.SnippetCodes[i].CompileError != nil {
					output.SnippetErrorCount = output.SnippetErrorCount + 1
				}
			}

			var message = getMessage(data, output)
			fmt.Printf("%s: %s\n", strings.ToUpper(output.Severity), message)
		}

	}
}

var suppressed = make(map[int]int)

func processRules(data map[string]interface{}, rules []*Rule, severity int) {
	for _, rule := range rules {
		_, isSuppressed := suppressed[rule.Id]

		level, err := severityLevel(rule.Severity)
		maybeDieWithoutMessage(err)
		rule.SeverityLevel = level

		if rule.SeverityLevel <= severity && !isSuppressed {

			// Compile Rule
			rule.Code.Expression = rule.Expression
			rule.Code.compile(data)
			level, err := severityLevel(rule.Severity)
			maybeDieWithoutMessage(err)
			rule.SeverityLevel = level

			// Compile Snippets
			rule.SnippetCodes = make([]*Code, len(rule.SnippetExpressions))
			for i, snippet := range rule.SnippetExpressions {
				rule.SnippetCodes[i] = &Code{Expression: snippet}
				rule.SnippetCodes[i].compile(data)
				if rule.SnippetCodes[i].CompileError != nil {
					rule.SnippetErrorCount = rule.SnippetErrorCount + 1
				}
			}

			// Run Rule
			if rule.Code.CompileError == nil {
				output, err := expr.Run(rule.Code.Program, data)

				if err != nil {
					rule.Code.RunError = err
					errorCount = errorCount + 1
				} else {
					switch output.(type) {
					case bool:
						if output.(bool) {
							var message = getMessage(data, rule)
							fmt.Printf("%s: %s\n", strings.ToUpper(rule.Severity), message)
							for _, item := range rule.Suppresses {
								suppressed[item] = item
							}
						}
					default:
						rule.Code.RunError = errors.New("expression didn't result in a boolean value")
					}
				}
			}
		}
	}
}

func getMessage(data map[string]interface{}, rule Printable) string {
	rule.Snippets()
	if len(rule.Snippets()) == 0 {
		return rule.Message()
	} else {
		snippetResults := make([]interface{}, len(rule.Snippets()))
		for i, code := range rule.Snippets() {
			if code.CompileError != nil {
				snippetResults[i] = "<compile error>"
			} else {
				code.run(data)
				if code.RunError != nil {
					snippetResults[i] = "<run error>"
					//rule.SnippetErrorCount = rule.SnippetErrorCount + 1
				} else {
					snippetResults[i] = code.Output
				}
			}
		}
		output := fmt.Sprintf(rule.Message(), snippetResults...)
		if len(output) > 1000 && rule.AllowLongMessage() == false {
			output = output[0:1000] + " ... <truncated>"
		}
		return output
	}
}

func processLoops(data map[string]interface{}, loops []*Loop, severity int) {
	for _, loop := range loops {
		loop.Code.Expression = loop.Expression
		loop.Code.compile(data)
		if loop.Code.CompileError != nil {
			continue
		}
		loop.Code.run(data)
		if loop.Code.RunError != nil {
			continue
		}
		// The expression ran, so we figure out the type (array or map) and recurse
		switch loop.Code.Output.(type) {
		case map[interface{}]interface{}:
			for k, v := range loop.Code.Output.(map[interface{}]interface{}) {
				d := make(map[string]interface{})
				if len(loop.Names) == 0 {
					loop.Names = []string{"key", "value"}
				}
				if len(loop.Names) == 2 {
					d["outer"] = data
					d[loop.Names[0]] = k
					d[loop.Names[1]] = v
					processValues(d, loop.Values)
					processOutputs(d, loop.Outputs, severity)
					processRules(d, loop.Rules, severity)
					processLoops(d, loop.Loops, severity)
				}
				loop.Code.RunError = errors.New("wrong number of names for map")
			}
		case []interface{}:
			for _, v := range loop.Code.Output.([]interface{}) {
				d := make(map[string]interface{})
				if len(loop.Names) == 0 {
					loop.Names = []string{"item"}
				}
				if len(loop.Names) == 1 {
					d["outer"] = data
					d[loop.Names[0]] = v
					processValues(d, loop.Values)
					processOutputs(d, loop.Outputs, severity)
					processRules(d, loop.Rules, severity)
					processLoops(d, loop.Loops, severity)
				}
			}
		default:
			println("Oops")
		}
	}
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
	processOutputs(data, config.Outputs, severity)
	processRules(data, config.Rules, severity)
	processLoops(data, config.Loops, severity)

	if errorCount > 0 {
		fmt.Printf("WARNING: There are %v errors\n", errorCount)
	}

	if showErrors {
		printErrors(config)
	}
}

func reportError(format string, parameters ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, parameters)
}

func printErrors(config *Config) {
	reportError("\n")

	for _, value := range config.Values {
		if value.Code.CompileError != nil || value.Code.RunError != nil {
			reportError("Error in Value: %v\n", value.Id)
			reportError("  Expression: %s\n", value.Expression)
			if value.Code.CompileError != nil {
				reportError("  Compile Error: %v\n", value.Code.CompileError)
			}
			if value.Code.RunError != nil {
				reportError("  Run Error: %v\n", value.Code.RunError)
			}
		}
	}

	for _, rule := range config.Rules {
		if rule.Code.CompileError != nil || rule.Code.RunError != nil || rule.SnippetErrorCount > 0 {
			reportError("Error in Rule: %v\n", rule.Id)
			if rule.Code.CompileError != nil || rule.Code.RunError != nil {
				reportError("  Expression: %s\n", rule.Expression)
			}
			if rule.Code.CompileError != nil {
				reportError("  Compile Error: %v\n", rule.Code.CompileError)
			}
			if rule.Code.RunError != nil {
				reportError("  Run Error: %v\n", rule.Code.RunError)
			}
			if rule.SnippetErrorCount > 0 {
				for _, snippet := range rule.SnippetCodes {
					reportError("  Snippet Expression: %s\n", snippet.Expression)
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
