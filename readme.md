# Redpanda Config Evaluator

## Purpose

This tool validates the content of YAML files against a supplied rules file in order to find problems in a programmatic,
repeatable manner.

## Build

```shell
go build -o redpanda-config-evaluator
```

## Usage

```shell
./redpanda-config-evaluator -h    
```

```text
Usage of ./redpanda-config-evaluator:
  -data string
        yaml file to validate (default "data.yaml")
  -errors
        show rule processing errors
  -rules string
        validation rules (default "rules.yaml")
  -severity string
        severity level to report: info, warning or error (default "info")
```

## Rules

The rules are specified in YAML as follows:

```yaml
- id: 0
  message: redpanda.developer_mode is enabled
  category: general
  severity: info
  expression: redpanda.developer_mode == true
```

### Expressions

Expressions are written using https://expr.medv.io/, which is a safe, fast and intuitive expression evaluator for Go.

> Every rule expression should return a boolean value to indicate pass/fail

### Severity

There are three levels of rule severity: `info`, `warning` and `error`. By default, all rules are evaluated
at runtime and reported on. If required, the severity can be increased to warn or error (suppress the evaluation of
less-critical rules).

### Rule Suppression

In some circumstances, it may be required to suppress rule evaluation if another rule has already reported a finding.

For example:

```yaml
- id: 1
  message: topic auto creation is enabled and developer mode is disabled
  category: general
  severity: warning
  expression: >
    redpanda.auto_create_topics_enabled == true &&
    redpanda.developer_mode == false
  suppresses: [2]

- id: 2
  message: topic auto creation is enabled
  category: general
  severity: info
  expression: redpanda.auto_create_topics_enabled == true
```

In this example, we can see that if the first rule evaluates as true, then there is no need for
the second rule to be evaluated. This can be achieved by adding `suppresses: [2]` to the definition of the first rule.

The `suppresses` field takes an array of rule IDs that should be suppressed.

### Dynamic Messages

While most rules will only need a static message, the may be scenarios in which a more dynamic message is helpful.

In order to support this, the tool allows the definition of snippets, which is a list of expressions that result in data to be
included within the message. For example:

```yaml
- id: 6
  message: redpanda.topic_partitions_per_shard is set to %v, which is too high
  category: test
  snippets: [redpanda.topic_partitions_per_shard]
  severity: warning
  expression: redpanda.topic_partitions_per_shard > 1000
 ```

In this example, we can see that the number of topic partitions per shard is evaluated as a snippet expression, which is then 
included in the message in the `%v` location. The message uses `fmt.Sprintf` format specifiers.

> Unlike rule expressions (which must return a boolean value), message snippets can return a value of any type.

## Errors

There are two main sources of errors relating to expression evaluation:

- rules that are always broken (say due to just being incorrectly written), v.s.
- rules that are contextually broken for a specific data file (say due to a rule referencing a field that doesn't exist)

By default, the tool will suppress the output of evaluation errors, but these can be included by adding the `-errors` flag.