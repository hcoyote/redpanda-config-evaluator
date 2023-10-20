# Redpanda Config Evaluator

## Purpose

This tool validates the content of YAML and JSON files against a supplied rules file in order to find problems in a programmatic,
repeatable manner.

## Build

```shell
go build -o evaluator
```

## Usage

```shell
./evaluator -h    
```

```text
Usage of ./evaluator:
  -data string
        YAML / JSON file to validate (default "data.json")
  -errors
        show rule processing errors (default true)
  -rules string
        validation rules (default "rules.yaml")
  -severity string
        severity level: info, warning, error (default "info")

```

# Rules

The rules are specified in YAML as follows:

```yaml
values:
  ...
loop:
  ...
rules:
  - id: 0
    message: redpanda.developer_mode is enabled
    category: general
    severity: info
    predicate: redpanda.developer_mode == true
```

### Predicates

Predicate expressions (which determine whether a rule should fire) are written using [Expr](https://expr.medv.io/), an expression evaluator for Go.

> Every predicate expression should return a boolean value to indicate pass/fail

### Severity

There are three levels of rule severity: `info`, `warning` and `error`. By default, all rules are evaluated
at runtime and reported on. If required, the severity can be increased to warn or error (suppress the evaluation of
less-critical rules).

### Rule Suppression

In some circumstances, it may be required to suppress rule evaluation if another rule has already reported a finding.

For example:

```yaml
rules:
  - id: 1
    message: topic auto creation is enabled and developer mode is disabled
    category: general
    severity: warning
    predicate: >
      redpanda.auto_create_topics_enabled == true &&
      redpanda.developer_mode == false
    suppresses: [2]

  - id: 2
    message: topic auto creation is enabled
    category: general
    severity: info
    predicate: redpanda.auto_create_topics_enabled == true
```

In this example, we can see that if the first rule evaluates as true, then there is no need for
the second rule to be evaluated. This can be achieved by adding `suppresses: [2]` to the definition of the first rule.

The `suppresses` field takes an array of rule IDs that should be suppressed.

### Dynamic Messages

While many rules will only need a static message, the may be scenarios in which a more dynamic message is helpful.

In order to support this, the tool allows the definition of snippets, which is a list of expressions that result in data to be
included within the message. For example:

```yaml
- id: 6
  message: redpanda.topic_partitions_per_shard is set to %v, which is too high
  category: test
  snippets: [redpanda.topic_partitions_per_shard]
  severity: warning
  predicate: redpanda.topic_partitions_per_shard > 1000
 ```

In this example, we can see that the number of topic partitions per shard is evaluated as a snippet expression, which is then 
included in the message in the `%v` location. The message uses `fmt.Sprintf` format specifiers.

> Unlike rule expressions (which must return a boolean value), message snippets can return a value of any type.

# Values

In addition to rules, the evaluator allows the creation of values, which are named expressions that are evaluated,
stored and made available in subsequent expressions. For example, we could create a value called `topics`, that contains
a map from topic name to the topic metadata

For example:

rules.yaml:
```yaml
values:

  - name: 'topic-metadata'
    expression: 'items | filter(.Name == "metadata") | map(.Response.Topics) | first() | toPairs()'

rules:

  - id: 'topics-with-more-than-10-partitions'
    message: 'There are %v topics with more than 10 partitions: %v'
    truncate: 'false'
    snippets: [ 'topic-metadata | count(len(#[1].Partitions) > 10)',
                'topic-metadata | filter(len(#[1].Partitions) > 10) | map(string(#[0]) + ":" + string(len(#[1].Partitions)))' ]
    category: 'topic summary'
    severity: 'info'
```

Here we can see a value called `topic-metadata`, which is used within the snippets of a rule.

# Loops

Highly nested YAML/JSON documents can make authoring expressions complex. In some of these cases, it can be simpler to create a loop.

A loop is defined using two items: an expression that returns an array or a map, and a list of names (a single name for an array; key and value names for a map).

For every entry in the array or map, the nested list of rules is evaluated.

## Collation

If a rule contains a `collate: [...]` list, then the snippets are evaluated and the results are collated into an array and made available to rules that execute 
after the loop has concluded.

For example:

rules.yaml:
```yaml
loop:
  - names: ['topic-name', 'config']
    expression: 'items | filter(.Name == "topic_configs") | map(.Response) | first() | map([.Name, .Configs]) | fromPairs()'
    rules:
      - id: '263939cb-6702-4e98-88e2-fdd5769337fc'
        collate: ['topics_with_some_specific_settings']
        predicate: >
          (config | one(.Key == "storage.setting" && .Value == "foo")) &&
          (config | one(.Key == "compaction.setting" && .Value == "bar"))
        snippets: ['topic-name']

rules:

  - id: '27d8028c-a5a2-480d-9989-a2ba5b2dccb7'
    message: '%v topics have specific retention settings: %v'
    predicate: 'len(topics_with_some_specific_settings) > 0'
    snippets: ['len(topics_with_some_specific_settings)',
               'topics_with_some_specific_settings']
```

Here we can see that a loop is defined over topics and their configurations. For each topic, the settings are evaluated by the rule predicate. If the predicate
evaluates as true, the snippet (in this example, the topic name) is collated into an array called `topics_with_some_specific_settings`.

Once the loop is concluded, the subsequent rule evaluates the collated list of topic names. If the length is > 0, then the rule is triggered and reported.

## Loops within Loops

The tool also supports the definition of loops within loops, allowing for a very powerful approach to rule evaluation.

## Outer Variables

For rules that run within a loop context, the parent variables are still accessible: simply prefix the names with `outer.` in order to access them as usual.


# Input Data

The evaluator accepts both YAML and JSON input files. The file to be processed is specified using the `-data` command line option.

## Map-based Input
When the top-level of the YAML/JSON data structure is a map, the keys of the map are directly available as variables within the expression language. For example:

data.json:
```json
{
  "name" : "Toaster",
  "parts" : {
    "Electrical|Descriptor1" : {
      "group" : "Electrical",
      "id" : "Part1",
      "description" : "Heating Element",
      "compat" : "B293"
    },
    "Exterior|Descriptor2" : {
      "group" : "Exterior",
      "id" : "Part2",
      "description" : "Lever",
      "compat" : "18A"
    }
  }
}
```

rules.yaml:
```yaml
rules:
  - id: 0
    message: 'There are %v parts'
    snippets: ['len(parts)']
```

Notice that ```parts``` (a top-level map key) is used in the expression.

```shell
go run main.go -rules rules.yaml -data example.json 
```
```text
INFO: There are 2 parts
```

## Array-based Input
When the top-level of the YAML/JSON data is an array, the items of the array are made available as `items` within the expression language. For example:

data.json:
```json
[
  {
    "color": "red",
    "value": "#f00"
  },
  {
    "color": "green",
    "value": "#0f0"
  },
  {
    "color": "blue",
    "value": "#00f"
  }
]
```

rules.yaml:
```yaml
rules:
  - id: 0
    message: 'There are %v colors'
    snippets: ['len(items)']
```

Notice that ```items``` is used in the expression.

```shell
go run main.go -rules rules.yaml -data example.json 
```
```text
INFO: There are 3 colors
```


# Errors

There are two main sources of errors relating to expression evaluation:

- Rules with a broken expression (predicate or snippet), v.s.
- Rules that break for a specific data file (maybe due to a missing field) that would otherwise work as expected

By default, the tool will suppress the output of evaluation errors, but these can be included by adding the `-errors` flag.