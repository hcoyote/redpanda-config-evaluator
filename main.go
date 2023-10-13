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

type Rule struct {
	Id                int      `yaml:"id"`
	Category          string   `yaml:"category"`
	Message           string   `yaml:"message"`
	Description       string   `yaml:"description"`
	Severity          string   `yaml:"severity"`
	Expression        string   `yaml:"expression"`
	Suppresses        []int    `yaml:"suppresses"`
	Snippets          []string `yaml:"snippets"`
	SeverityLevel     int
	Program           *vm.Program
	CompileError      error
	RunError          error
	SnippetErrors     []error
	SnippetErrorCount int
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

func readRules(filename string) (error, []*Rule) {
	// Read the file
	content, err := os.ReadFile(filename)
	if err != nil {
		return err, nil
	}

	// Create a slice to hold the YAML data
	var result []*Rule

	// Unmarshal the YAML data into the map
	err = yaml.Unmarshal(content, &result)
	return err, result
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

func compile(data map[string]interface{}, rules []*Rule) {
	for _, rule := range rules {
		rule.Expression = strings.TrimSuffix(rule.Expression, "\n")
		options := []expr.Option{
			expr.Function("uniq", uniq, new(func([]any) []any)),
			expr.Env(data),
		}
		program, err := expr.Compile(rule.Expression, options...)
		rule.Program = program
		rule.CompileError = err
		if err != nil {
			errorCount = errorCount + 1
		}
		rule.SeverityLevel, err = severityLevel(rule.Severity)
		maybeDieWithoutMessage(err)
		rule.SnippetErrors = make([]error, 0)
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

func process(data map[string]interface{}, rules []*Rule, severity int) {
	suppressed := make(map[int]int)
	for _, rule := range rules {
		_, isSuppressed := suppressed[rule.Id]
		if rule.SeverityLevel <= severity && !isSuppressed {
			if rule.CompileError == nil {
				output, err := expr.Run(rule.Program, data)

				if err != nil {
					rule.RunError = err
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
						rule.RunError = errors.New("expression didn't result in a boolean value")
					}
				}
			}
		}
	}
}

func getMessage(data map[string]interface{}, rule *Rule) string {
	if len(rule.Snippets) == 0 {
		return rule.Message
	} else {
		snippets := make([]any, len(rule.Snippets))
		for i, s := range rule.Snippets {

			options := []expr.Option{
				expr.Env(data),
				expr.Function("uniq", uniq, new(func([]any) []any)),
			}

			program, err := expr.Compile(s, options...)
			if err != nil {
				rule.SnippetErrors = append(rule.SnippetErrors, err)
			}
			value, err := expr.Run(program, data)
			if err != nil {
				rule.SnippetErrors = append(rule.SnippetErrors, err)
				snippets[i] = "<snippet error>"
				rule.SnippetErrorCount = rule.SnippetErrorCount + 1
				errorCount = errorCount + 1
			} else {
				rule.SnippetErrors = append(rule.SnippetErrors, nil)
				snippets[i] = value
			}

		}
		return fmt.Sprintf(rule.Message, snippets...)
	}
}

func main() {
	var rulesFile string
	flag.StringVar(&rulesFile, "rules", "rules.yaml", "validation rules")
	var dataFile string
	flag.StringVar(&dataFile, "data", "data.json", "YAML / JSON file to validate")
	var severityFlag string
	flag.StringVar(&severityFlag, "severity", "info", "severity level: info, warning, error")
	var showErrors bool
	flag.BoolVar(&showErrors, "errors", true, "show rule processing errors")
	flag.Parse()

	err, data := readData(dataFile)
	maybeDie(err, fmt.Sprintf("Unable to read data: %s", err))
	err, rules := readRules(rulesFile)
	compile(data, rules)
	severity, _ := severityLevel(severityFlag)
	process(data, rules, severity)

	if errorCount > 0 {
		fmt.Printf("WARNING: There are %v errors\n", errorCount)
	}

	if showErrors {
		fmt.Fprintf(os.Stderr, "\n")
		for _, rule := range rules {
			if rule.CompileError != nil || rule.RunError != nil || rule.SnippetErrorCount > 0 {
				fmt.Fprintf(os.Stderr, "Error in Rule: %v\n", rule.Id)
				if rule.CompileError != nil || rule.RunError != nil {
					fmt.Fprintf(os.Stderr, "  Expression: %s\n", rule.Expression)
				}
				if rule.CompileError != nil {
					fmt.Fprintf(os.Stderr, "  Compile Error: %v\n", rule.CompileError)
				}
				if rule.RunError != nil {
					fmt.Fprintf(os.Stderr, "  Run Error: %v\n", rule.RunError)
				}
				if rule.SnippetErrorCount > 0 {
					for i, snippet := range rule.Snippets {
						if rule.SnippetErrors[i] != nil {
							fmt.Fprintf(os.Stderr, "  Snippet Expression: %s\n", snippet)
							fmt.Fprintf(os.Stderr, "       Snippet Error: %v\n", rule.SnippetErrors[i])
						}
					}

				}
			}
		}
	}

	//if showErrors {
	//	if len(processingErrors) > 0 {
	//		fmt.Fprintf(os.Stderr, "Processing errors:\n")
	//		for _, err := range processingErrors {
	//			fmt.Fprintf(os.Stderr, "\n")
	//			fmt.Fprintf(os.Stderr, "%s\n", err)
	//		}
	//	}
	//}
}
