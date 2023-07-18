# Examples

## Core functionality

The following example illustrates the core components of Timberlake. 

### Config

Test case directory assumes execution occurs from project root

```
profiles:
- "default"
testcases:
  directory: "examples/" 
  recurse: false
vectr:
  use_vectr: false
```

### Test case 

Full test case file: [create_iam_user.yml](create_iam_user.yml)

**Arguments**

```
arguments:
  iam_user: testuser
```

Test case content is rendered via Jinja2 so the arguments can be accessed using the format `{{ argument }}`. 
All test cases will be able to access the value `testuser` by referring to `iam_user` (as `{{ iam_user }}`). 

**Step 1 - Execution**

```
- name: Create user
  block:
    phase: execution
    type: inline
    content: |
      iam = sessions["default"].client("iam")
      primitives.IAM.create_user(iam, user_name="{{ iam_user }}")
      set_value("user", "{{ iam_user }}")
```

The first block creates a user. Breaking down the content section line-by-line:

- > iam = sessions["default"].client("iam")
    - Create a boto3 client for the IAM service using the default profile provided by the config
- > primitives.IAM.create_user(iam, user_name="{{ iam_user }}")
    - Uses the built-in `primitives` object to create an IAM user of the name specified in the argument `iam_user`
    - Users are also free to call API actions directly. For example, they can create a user via `iam.create_user(...)`, which is the `boto3` function. Any valid Python code can be used.
- > set_value("user", "{{ iam_user }}")
    - Uses the built-in `set_value` function to persist the value of the `iam_user` argument to the key `user`
    - This step is not necessarily required but is useful for demonstration purposes

**Step 2 - Cleanup**

```
- name: Delete user
  block:
    phase: cleanup
    type: inline
    content: |
      iam = sessions["default"].client("iam")
      primitives.IAM.delete_user(iam, user_name=get_value("user"))
```

The second block deletes the user created in the first step. Breaking down the content section line-by-line:

- > iam = sessions["default"].client("iam")
    - Create a boto3 client for the IAM service using the default profile provided by the config
    - Notice that this must be performed again despite also being called in the previous step. This is because steps do not share an execution context and only items stored via `set_value` can be persisted
- > primitives.IAM.delete_user(iam, user_name=get_value("user"))
    - Uses the built-in `primitives` object to delete an IAM user of the name retrieved from the built-in `get_value`, which gets the value stored under the key `user`.
    - Primitives encapsulate compound operations and expose them as single operations. In the case of deleting AWS IAM users, you must first remove any policies from the user. `IAM.delete_user` takes care of these prerequisite actions. Primitives will also indicate a resource was created with Timberlake for certain operations. In the first step, calling `IAM.create_user` will create the user `iam_user` under the path `/timberlake/`.
    - Values set and retrieved using `set_value` and `get_value` will also be logged to the logfile

**Step 3 - Check logs**

When looking at output from the command-line utility, only a basic true/false is reported for the success of a test case step execution. 
For additional information, refer to the log file (default location is .timberlake.log).

Example log for above example:

```
2023-02-14 13:45:30,401 | INFO | Timberlake
2023-02-14 13:45:30,401 | INFO | Running phases: execution setup cleanup
2023-02-14 13:45:30,401 | INFO | Phase started: setup
2023-02-14 13:45:30,401 | INFO | Phase completed: setup
2023-02-14 13:45:30,401 | INFO | Phase started: execution
2023-02-14 13:45:30,459 | INFO | {"service": "iam", "operation": "CreateUser", "params": {"Path": "/timberlake/", "UserName": "testuser"}, "region": "aws-global"}
2023-02-14 13:45:30,618 | INFO | setting value of "user" to "testuser" 
2023-02-14 13:45:30,619 | INFO | execution - Create user - Success: True
2023-02-14 13:45:30,619 | INFO | Phase completed: execution
2023-02-14 13:45:30,619 | INFO | Phase started: cleanup
2023-02-14 13:45:30,658 | INFO | resolved value of "user" to "testuser"
2023-02-14 13:45:30,712 | INFO | {"service": "iam", "operation": "ListUserPolicies", "params": {"UserName": "testuser"}, "region": "aws-global"}
2023-02-14 13:45:30,869 | INFO | {"service": "iam", "operation": "ListAttachedUserPolicies", "params": {"UserName": "testuser"}, "region": "aws-global"}
2023-02-14 13:45:30,919 | INFO | {"service": "iam", "operation": "DeleteUser", "params": {"UserName": "testuser"}, "region": "aws-global"}
2023-02-14 13:45:30,974 | INFO | cleanup - Delete user - Success: True
2023-02-14 13:45:30,975 | INFO | Phase completed: cleanup
```


