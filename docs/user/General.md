# General user notes

## Phases

Test case steps are executed sequentially based on the phase. The order is: setup -> execution -> cleanup. Test cases can have multiple steps in the same phase as well as no steps in a phase. 

## VECTR setup

The following items are required to use the VECTR integration

- A VECTR instance. If the instance uses a certificate not trusted by the host running Timberlake, set the TIMBERLAKE_DEBUG to true to disable certificate validation. In the config file, make sure to also include the port.
- API credentials. These can be exported by selecting the user icon in the top-right -> profile -> API Keys -> Create API Key
- An existing database in VECTR. This can be created by selecting the database icon in the top-right -> Select Session Database -> + -> Enter value -> Submit

## Test case creation

### Convenience features

The following Python functions/variables are exposed inside the execution context of every test case step:

- all locals from the parent
- all globals from the parent
- set_value(key, value) : provides a mechanism to persist data between steps for the same test case
- get_value(key) : retrieve persisted data
- generate_session(...) : alias for cloud provider-specific client session creation function
    - AWS -> generate_boto_session(...) from timberlake.aws : returns a boto3 Session() object

### Notes

- When using a file instead of inline code, if the path to the file is not an absolute path, it is treated as relative to the location of the test case that refers to it.

## Provider-specific features

### AWS 

The following Python functions/variables are exposed inside the execution context of every test case step when the provider is AWS:

- sessions : list of boto3 Sessions for each session provided in the config. These sessions are configured with additional API-level logging
- boto3 : boto3 library
- waiters : additional boto3 waiters
- primitives : common compound operations, such as creating a role then attaching a permission policy
- generate_session : create a session with the Timberlake logger
- policies : premade permission/trust/resource policies

see also: `timberlake.aws:generate_aws_ctx`

## Environment vars

The following environment variables can be used to control Timberlake functionality (managed under `settings.py`).

|Variable|Use|Default|Notes|
|---|---|---|---|
|TIMBERLAKE_LOGFILE|Log file for API calls|.timberlake.log||
|TIMBERLAKE_DEBUG|Enable debug mode|False|Will disable certificate validation for VECTR connections|
|TIMBERLAKE_VECTR_ORGID|VECTR organization ID|1cf413ba-326a-4d18-979c-367eb1306f69||
|TIMBERLAKE_VECTR_GQLURI|URI to VECTR GraphQL endpoint|/sra-purpletools-rest/graphql|Useful for when VECTR is behind a reverse proxy|
