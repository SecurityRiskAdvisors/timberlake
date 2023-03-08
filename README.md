# AWS Attack Automation

Timberlake is an AWS attack automation utility that can execute one or more test cases. You can read the release blog here: [link](https://sra.io/blog/timberlake-aws-attack-automation/)

Test cases are individual YAML documents that define the setup, execution, and cleanup steps for an attack procedure. These documents contain both metadata about the attack (e.g. MITRE mappings, permissions) as well as Python code for executing the attack.

Timberlake is designed with modularity in mind. Test cases are defined and managed outside the tool and can be swapped around as needed for different execution scenarios. 

Notable features of Timberlake:

- Support for multiple credential profiles
- Premade operations avaiable to all test cases (e.g. compound API actions, canned policies, etc)
- API-level logging, including parameters
- [VECTR](https://github.com/SecurityRiskAdvisors/vectr) integration for tracking attack details

Example use can be found in [examples](examples/)

*Note: Test cases should ideally be run in a non-production account*

# Install

> pip install dist/*.whl

# Usage

```
usage: timberlake [-h] -c CONFIG [-p PHASES] [-a ARGS]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file path
  -p {execution,setup,cleanup} [{execution,setup,cleanup} ...], --phases {execution,setup,cleanup} [{execution,setup,cleanup} ...]
                        list of phases to execute; default = all
  -a ARGS, --args ARGS  args file path
```

- Config : path to config file; must exist
- Phases : one or more phase names to execute; order doesn't matter
- Args : YAML document of key-value pairs to override test case args

# Details

## Annotated schemas

Refer to [test-case-schema.yml](test-case-schema.yml) for test case schema details

Refer to [config.yml](config.yml) for config file schema details

## Attack sequencing

### Basic execution

Basic execution mode refers to execution without using the VECTR integrations.
The execution sequence is as follows:

1. Collect test cases 
2. Run pre-execution hooks (e.g logging)
3. Run test case blocks by phase (setup -> execution -> cleanup)
4. Run post-execution hooks 
5. Exit

Execution details are logged to the TIMBERLAKE_LOGFILE location.

### VECTR execution

VECTR execution mode refers to execution with added VECTR integration (via GraphQL). 
The excution sequence is as follows:

1. Collect test cases
2. Create assessment groups and campaigns in VECTR
3. Run pre-execution hooks (e.g logging)
4. Run test case blocks by phase (setup -> execution -> cleanup)
5. Create test case in VECTR 
   - all test cases are tagged with "timberlake"
   - test cases with errors are tagged with "error" 
6. Run post-execution hooks 
7. Write ATTiRe log to location specified in config. Details captured in ATTiRe log: 
    - Cloud control plane API call details
8. Exit

Note: Only code blocks in the execution phase create a test case and ATTiRe log

# See also

- https://github.com/FSecureLABS/leonidas : is a very similar concept, but test cases are performed as Lambda functions; test case schema is conceptually similar to what this tool wants to do and was a source of design inspiration

