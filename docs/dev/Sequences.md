# Sequences

The *Sequence classes in [sequence.py](../../timberlake/sequence.py) handle test case execution. 
Sequences use hooks that are called both before and after test case execution to implement arbitrary functionality. Developers can either override these hooks or register their own hooks.

## Pre-execution hooks

The following hooks are called before test case execution:

- _pre_execution_hook : used for arbitrary functionality

## Post-execution hooks

The following hooks are called after test case execution:

- _post_execution_hook : used for arbitrary functionality
- _log_details_hook : used for logging details only

## Hook registration

Sequences use the register_hooks function to register an arbitrary function as a hook. Functions registered as pre-execution hooks receive the SequencePreExecContext object and functions registered as post-execution hooks receive the SequencePostExecContext object. Both object types contain the test csae, test case step, step block, and phase of the executed test case. The SequencePostExecContext also contains the result boolean. This value is set by default based on the script code executed but can be also overridden. If the script raises an exception, the result is set to False, otherwise True. If the script returns a "result" variable and raises no exceptions that value is used.

Developers can alternatively subclass the abstract parent Sequence class then implement the default hook functions directly.




