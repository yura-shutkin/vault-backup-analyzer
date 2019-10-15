# Vault backup analyzer

This script is built for analyzing [vault](https://vaultproject.io) backups stored at [consul](https://consul.io) cluster
<!--
## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them

```
Give examples
```

### Installing

A step by step series of examples that tell you how to get a development env running

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.
-->
## metrics

### Metrics template 
| metric_name | labels |
| --- | --- |
| vba_auth_backend_objects_count | type, mount_point |
| vba_auth_backend_objects_size | type, mount_point |
| vba_auth_backend_roles_count | type, mount_point |
| vba_auth_backend_roles_size | type, mount_point |
| vba_auth_backend_role_ids_count | type, mount_point |
| vba_auth_backend_role_ids_size | type, mount_point |
| vba_auth_backend_secret_ids_count | type, mount_point |
| vba_auth_backend_secret_ids_size | type, mount_point |
| vba_auth_backend_secret_ids_accessors_count | type, mount_point |
| vba_auth_backend_secret_ids_accessors_size | type, mount_point |
| vba_auth_backend_tokens_count | type, mount_point |
| vba_auth_backend_tokens_size | type, mount_point |
| vba_auth_backend_token_renew_self_count | type, mount_point |
| vba_auth_backend_token_renew_self_size | type, mount_point |
| vba_auth_backend_token_accessors_count | type, mount_point |
| vba_auth_backend_token_accessors_size | type, mount_point |
| vba_auth_backend_users_count | type, mount_point |
| vba_auth_backend_users_size | type, mount_point |
| vba_auth_backend_groups_count | type, mount_point |
| vba_auth_backend_groups_size | type, mount_point |
| vba_secrets_engine_objects_count | type, mount_point, version |
| vba_secrets_engine_objects_size | type, mount_point, version |
| vba_secrets_engine_secrets_count | type, mount_point, version |
| vba_secrets_engine_secrets_size | type, mount_point, version |
| vba_secrets_engine_secrets_archives_count | type, mount_point, version |
| vba_secrets_engine_secrets_archives_size | type, mount_point, version |
| vba_secrets_engine_secrets_policies_count | type, mount_point, version |
| vba_secrets_engine_secrets_policies_size | type, mount_point, version |
| vba_secrets_engine_secrets_versions_count | type, mount_point, version |
| vba_secrets_engine_secrets_versions_size | type, mount_point, version |
| vba_system_objects_count | type |
| vba_system_objects_size | type |

### Metrics example
| metric_name | valid type labels | valid mount_point labels | valid version labels |
| --- | --- | --- | --- |
| vba_auth_backend_objects_count | approle, userpass, kubernetes, LDAP, token | * | N/A |
| vba_auth_backend_roles_count | approle, kubernetes | * | N/A |
| vba_auth_backend_role_ids_count | approle | * | N/A |
| vba_auth_backend_secret_ids_count | approle | * | N/A |
| vba_auth_backend_secret_ids_accessors_count | approle | * | N/A |
| vba_auth_backend_tokens_count | userpass, approle, kubernetes, LDAP, token | * | N/A |
| vba_auth_backend_token_renew_self_count | userpass, approle, kubernetes, LDAP | * | N/A |
| vba_auth_backend_token_accessors_count | userpass, approle, kubernetes, LDAP, token | * | N/A |
| vba_auth_backend_users_count | userpass, LDAP | * | N/A |
| vba_auth_backend_groups_count | LDAP | * | N/A |
| vba_secrets_engine_objects_count | cubbyhole, transit, identity, kv | * | N/A |
| vba_secrets_engine_secrets_count | cubbyhole, transit, identity | * | '' |
| vba_secrets_engine_secrets_count | kv | * | '1' |
| vba_secrets_engine_secrets_count | kv | * | '2' |
| vba_secrets_engine_secrets_archives_count | kv, transit | * | '', '2' |
| vba_secrets_engine_secrets_policies_count | kv, transit | * | '', '2' |
| vba_secrets_engine_secrets_versions_count | kv | * | '2' |
| vba_system_objects_count | policy, core, audit_device, counters | N/A | N/A |

## License

This project is licensed under the MIT License - see the [LICENSE.md](/LICENSE.md) file for details
<!--
## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc
-->
