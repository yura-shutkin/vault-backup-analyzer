import hvac
import yaml


def enable_auth_backends(session, backends):
    for top_key in backends:
        for idx in range(len(backends[top_key])):
            session.sys.enable_auth_method(method_type=backends[top_key][idx]['method_type'],
                                           path=backends[top_key][idx]['mount_point'],
                                           config=backends[top_key][idx]['config'])


def create_policies(session, policies):
    for top_key in policies:
        for idx in range(len(policies[top_key])):
            session.sys.create_or_update_policy(
                name=policies[top_key][idx]['name'],
                policy=policies[top_key][idx]['policy']
            )


def create_userpass_users(session, userpass_users):
    for top_key in userpass_users:
        for idx in range(len(userpass_users[top_key])):
            session.create_userpass(
                username=userpass_users[top_key][idx]['name'],
                password=userpass_users[top_key][idx]['password'],
                policies=userpass_users[top_key][idx]['policies'],
                mount_point=userpass_users[top_key][idx]['mount_point']
            )


def create_approles(session, approles):
    for top_key in approles:
        for idx in range(len(approles)):
            session.create_role(
                role_name=approles[top_key][idx]['name'],
                mount_point=approles[top_key][idx]['mount_point'],
                param=approles[top_key][idx]['params']
            )


def mount_secrets_engines(session, secrets_engines):
    for top_key in secrets_engines:
        for idx in range(len(secrets_engines[top_key])):
            session.sys.enable_secrets_engine(
                backend_type=secrets_engines[top_key][idx]['backend_type'],
                path=secrets_engines[top_key][idx]['mount_point'],
                description=secrets_engines[top_key][idx]['description'],
                config=secrets_engines[top_key][idx]['params'],
                options=secrets_engines[top_key][idx]['options']
            )


def write_kv1_secrets(session, mount_point, secrets):
    for top_key in secrets:
        for idx in range(len(secrets[top_key])):
            session.secrets.kv.v1.create_or_update_secret(
                path=secrets[top_key][idx]['path'],
                secret=secrets[top_key][idx]['data'],
                mount_point=mount_point
            )


def write_kv2_secrets(session, mount_point, secrets):
    for top_key in secrets:
        for idx in range(len(secrets[top_key])):
            session.secrets.kv.v2.create_or_update_secret(
                path=secrets[top_key][idx]['path'],
                secret=secrets[top_key][idx]['data'],
                mount_point=mount_point
            )


def open_yaml(path):
    with open(path, 'r') as auth_backends_file:
        result = yaml.load(auth_backends_file.read(), Loader=yaml.Loader)
    return result


if __name__ == '__main__':
    VAULT_ADDR = 'http://localhost:8200'
    ROOT_TOKEN = '12345'
    AUTH_BACKENDS = open_yaml('seed_configs/auth_backends.yml')
    POLICIES = open_yaml('seed_configs/policies.yml')
    USERPASS_USERS = open_yaml('seed_configs/userpass_users.yml')
    APPROLES = open_yaml('seed_configs/approles.yml')
    SECRETS_ENGINES = open_yaml('seed_configs/secrets_engines.yml')
    SECRETS = open_yaml('seed_configs/secrets.yml')

    ROOT_SESSION = hvac.Client(url=VAULT_ADDR, token=ROOT_TOKEN)

    enable_auth_backends(ROOT_SESSION, AUTH_BACKENDS)
    create_policies(ROOT_SESSION, POLICIES)
    create_userpass_users(ROOT_SESSION, USERPASS_USERS)
    create_approles(ROOT_SESSION, APPROLES)
    mount_secrets_engines(ROOT_SESSION, SECRETS_ENGINES)

    write_kv1_secrets(ROOT_SESSION, 'simple', SECRETS)
    write_kv2_secrets(ROOT_SESSION, 'secret', SECRETS)
