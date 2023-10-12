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
	Id            int      `yaml:"id"`
	Category      string   `yaml:"category"`
	Message       string   `yaml:"message"`
	Severity      string   `yaml:"severity"`
	Expression    string   `yaml:"expression"`
	Suppresses    []int    `yaml:"suppresses"`
	Snippets      []string `yaml:"snippets"`
	SeverityLevel int
	Program       *vm.Program
}

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

	var result map[string]interface{}
	err = yaml.Unmarshal(content, &result)

	return err, result
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
		program, err := expr.Compile(rule.Expression, expr.Env(data))
		maybeDie(err, fmt.Sprintf("Unable to compile function: %s", err))
		rule.Program = program
		rule.SeverityLevel, err = severityLevel(rule.Severity)
		maybeDieWithoutMessage(err)
	}
}

func process(data map[string]interface{}, rules []*Rule, severity int) []error {
	processingErrors := make([]error, 0)
	suppressed := make(map[int]int)
	for _, rule := range rules {
		_, isSuppressed := suppressed[rule.Id]
		if rule.SeverityLevel <= severity && !isSuppressed {
			output, err := expr.Run(rule.Program, data)
			if err != nil {
				processingErrors = append(processingErrors, err)
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
					fmt.Printf("Error: Expression %s resulted in output: %s\n", rule.Expression, output)
					die("Expression didn't result in a boolean result")
				}
			}
		}
	}
	return processingErrors
}

func getMessage(data map[string]interface{}, rule *Rule) string {
	if len(rule.Snippets) == 0 {
		return rule.Message
	} else {
		snippets := make([]any, len(rule.Snippets))
		for i, s := range rule.Snippets {
			value, err := expr.Eval(s, data)
			maybeDie(err, fmt.Sprintf("Unable to process snippet: %s", rule.Snippets[i]))
			snippets[i] = value
		}
		return fmt.Sprintf(rule.Message, snippets...)
	}
}

func main() {
	var rulesFile string
	flag.StringVar(&rulesFile, "rules", "rules.yaml", "validation rules")
	var dataFile string
	flag.StringVar(&dataFile, "data", "data.yaml", "yaml file to validate")
	var severityFlag string
	flag.StringVar(&severityFlag, "severity", "info", "severity level to report: info, warning or error")
	var showErrors bool
	flag.BoolVar(&showErrors, "errors", false, "show rule processing errors")
	flag.Parse()

	err, data := readData(dataFile)
	maybeDie(err, fmt.Sprintf("Unable to read data: %s", err))
	err, rules := readRules(rulesFile)
	compile(data, rules)
	severity, _ := severityLevel(severityFlag)
	processingErrors := process(data, rules, severity)
	if showErrors {
		if len(processingErrors) > 0 {
			fmt.Fprintf(os.Stderr, "Processing errors:\n")
			for _, err := range processingErrors {
				fmt.Fprintf(os.Stderr, "\n")
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	}
}
