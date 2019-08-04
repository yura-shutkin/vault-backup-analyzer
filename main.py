import json
import sys
import os

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway


class Metrics():
    token_count = Gauge('token_count', 'Number of tokens found in a backup')
    token_size = Gauge('token_size', 'Size of encrypted tokens found in a backup')

    @classmethod
    def get_empty(cls):
        return {k.set(0) for k in cls.__dict__}

    # token_count.labels(env='local', group='vault')
    # token_count.set(stats['token_count'])

    # total_count = 'Number of tokens found in a backup', 0


def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def process_backup(backup_file_name):
    statistics = {
        "f_name": backup_file_name,
        "token_count": 0,
        "token_size": 0,
        "token_accessor_count": 0,
        "token_accessor_size": 0,
        "policy_count": 0,
        "policy_size": 0,
        "secret_count": 0,
        "secret_size": 0,
        "group_count": 0,
        "group_size": 0,
        "approle_id_count": 0,
        "approle_id_size": 0,
        "approle_count": 0,
        "approle_size": 0,
        "secret_id_count": 0,
        "secret_id_size": 0,
        "userpass_user_count": 0,
        "userpass_user_size": 0,
        "approle_expire_count": 0,
        "approle_expire_size": 0,
        "ldap_expire_count": 0,
        "ldap_expire_size": 0,
        "token_expire_count": 0,
        "token_expire_size": 0,
        "userpass_user_expire_count": 0,
        "userpass_user_expire_size": 0,
    }
    buffer = ""
    count = 0

    with open(backup_file_name, 'r') as backup_file:
        for piece in read_in_chunks(backup_file):
            statistics, buffer, count = process_element(statistics, buffer + piece, count)
    return statistics


def process_element(statistics, buffer, items_count):
    def update_statistics(attribute, attr_val):
        nonlocal statistics
        statistics["{}_count".format(attribute)] += 1
        sizeof = sys.getsizeof(attr_val)
        statistics["{}_size".format(attribute)] += sizeof
        print('{}: Found a {} no {} with size {}'.format(statistics["f_name"], attribute,
                                                         statistics["{}_count".format(attribute)], sizeof))

    def search_for_dict():
        nonlocal buffer
        nonlocal items_count
        dict_start = buffer.find('{')

        if 0 != dict_start:
            buffer = buffer[dict_start:]
            dict_start = buffer.find('{')
        dict_end = buffer.find('}')

        if -1 != dict_end:
            items_count += 1
            print(items_count)
            found = buffer[dict_start: dict_end + 1]
            buffer = buffer[dict_end + 1:]
            return json.loads(found)
        else:
            return None

    element = search_for_dict()
    while element is not None:
        field = ''
        value = ''
        if 'Key' in element:
            field = 'Key'
            value = 'Value'
        if 'key' in element:
            field = 'key'
            value = 'value'

        if '' == field:
            print('No key field found')
            exit(1)

        if '/audit/' in element[field]:
            pass
        if '/auth/' in element[field]:
            if '/expire/' in element[field]:
                pass
            else:
                if '/group/' in element[field]:
                    update_statistics('group', element[value])
                if '/role_id/' in element[field]:
                    update_statistics('approle_id', element[value])
                if '/role/' in element[field]:
                    update_statistics('approle', element[value])
                if '/secret_id/' in element[field]:
                    update_statistics('secret_id', element[value])
                if '/user/' in element[field]:
                    update_statistics('userpass_user', element[value])
        if '/core/' in element[field]:
            pass
        if '/logical/' in element[field]:
            update_statistics('secret', element[value])
        if '/sys/' in element[field]:
            if '/token/' in element[field]:
                if '/id/' in element[field]:
                    update_statistics('token', element[value])
                if '/accessor/' in element[field]:
                    update_statistics('token_accessor', element[value])
            if '/policy/' in element[field]:
                update_statistics('policy', element[value])
            if '/expire/' in element[field]:
                if '/approle/' in element[field]:
                    update_statistics('approle_expire', element[value])
                if '/ldap/' in element[field]:
                    update_statistics('ldap_expire', element[value])
                if '/token/' in element[field]:
                    update_statistics('token_expire', element[value])
                if '/userpass/' in element[field]:
                    update_statistics('userpass_user_expire', element[value])

        element = search_for_dict()

    return statistics, buffer, items_count


def pretty(d, indent=0):
    for key, value in d.items():
        print('\t' * indent + str(key))
        if isinstance(value, dict):
            pretty(value, indent + 1)
        else:
            print('\t' * (indent + 1) + str(value))


def push_metrics(stats):
    registry = CollectorRegistry()

    token_count = Gauge('token_count', 'Number of tokens found in a backup', registry=registry)
    # token_count.labels(env='local', group='vault')
    token_count.set(stats['token_count'])
    token_size = Gauge('token_size', 'Size of encrypted tokens found in a backup', registry=registry)
    # token_size.labels(env='local', group='vault')
    token_size.set(stats['token_size'])

    token_accessor_count = Gauge('token_accessor_count', 'Number of token accessors found in a backup', registry=registry)
    # token_accessor_count.labels(env='local', group='vault')
    token_accessor_count.set(stats['token_accessor_count'])
    token_accessor_size = Gauge('token_accessor_size', 'Size of encrypted token accessors found in a backup', registry=registry)
    # token_accessor_size.labels(env='local', group='vault')
    token_accessor_size.set(stats['token_accessor_size'])

    policy_count = Gauge('policy_count', 'Number of policies found in a backup', registry=registry)
    # policy_count.labels(env='local', group='vault')
    policy_count.set(stats['policy_count'])
    policy_size = Gauge('policy_size', 'Size of encrypted policies found in a backup', registry=registry)
    # policy_size.labels(env='local', group='vault')
    policy_size.set(stats['policy_size'])

    secret_count = Gauge('secret_count', 'Number of secrets found in a backup', registry=registry)
    # secret_count.labels(env='local', group='vault')
    secret_count.set(stats['secret_count'])
    secret_size = Gauge('secret_size', 'Size of encrypted secrets found in a backup', registry=registry)
    # secret_size.labels(env='local', group='vault')
    secret_size.set(stats['secret_size'])

    group_count = Gauge('group_count', 'Number of groups found in a backup', registry=registry)
    # group_count.labels(env='local', group='vault')
    group_count.set(stats['group_count'])
    group_size = Gauge('group_size', 'Size of encrypted groups found in a backup', registry=registry)
    # group_size.labels(env='local', group='vault')
    group_size.set(stats['group_size'])

    approle_id_count = Gauge('approle_id_count', 'Number of approle_ids found in a backup', registry=registry)
    # approle_id_count.labels(env='local', group='vault')
    approle_id_count.set(stats['approle_id_count'])
    approle_id_size = Gauge('approle_id_size', 'Size of encrypted approle_ids found in a backup', registry=registry)
    # approle_id_size.labels(env='local', group='vault')
    approle_id_size.set(stats['approle_id_size'])

    approle_count = Gauge('approle_count', 'Number of approles found in a backup', registry=registry)
    # approle_count.labels(env='local', approle_='vault')
    approle_count.set(stats['approle_count'])
    approle_size = Gauge('approle_size', 'Size of encrypted approles found in a backup', registry=registry)
    # approle_size.labels(env='local', approle_='vault')
    approle_size.set(stats['approle_size'])

    secret_id_count = Gauge('secret_id_count', 'Number of secret_ids found in a backup', registry=registry)
    # secret_id_count.labels(env='local', group='vault')
    secret_id_count.set(stats['secret_id_count'])
    secret_id_size = Gauge('secret_id_size', 'Size of encrypted secret_ids found in a backup', registry=registry)
    # secret_id_size.labels(env='local', group='vault')
    secret_id_size.set(stats['secret_id_size'])

    userpass_user_count = Gauge('userpass_user_count', 'Number of userpass users found in a backup', registry=registry)
    # userpass_user_count.labels(env='local', group='vault')
    userpass_user_count.set(stats['userpass_user_count'])
    userpass_user_size = Gauge('userpass_user_size', 'Size of encrypted userpass users found in a backup',
                               registry=registry)
    # userpass_user_size.labels(env='local', group='vault')
    userpass_user_size.set(stats['userpass_user_size'])

    approle_expire_count = Gauge('approle_expire_count', 'Number of approle_expires found in a backup',
                                 registry=registry)
    # approle_expire_count.labels(env='local', group='vault')
    approle_expire_count.set(stats['approle_expire_count'])
    approle_expire_size = Gauge('approle_expire_size', 'Size of encrypted approle_expires found in a backup',
                                registry=registry)
    # approle_expire_size.labels(env='local', group='vault')
    approle_expire_size.set(stats['approle_expire_size'])

    ldap_expire_count = Gauge('ldap_expire_count', 'Number of ldap_expires found in a backup', registry=registry)
    # ldap_expire_count.labels(env='local', group='vault')
    ldap_expire_count.set(stats['ldap_expire_count'])
    ldap_expire_size = Gauge('ldap_expire_size', 'Size of encrypted ldap_expires found in a backup', registry=registry)
    # ldap_expire_size.labels(env='local', group='vault')
    ldap_expire_size.set(stats['ldap_expire_size'])

    token_expire_count = Gauge('token_expire_count', 'Number of token_expires found in a backup', registry=registry)
    # token_expire_count.labels(env='local', group='vault')
    token_expire_count.set(stats['token_expire_count'])
    token_expire_size = Gauge('token_expire_size', 'Size of encrypted token_expires found in a backup',
                              registry=registry)
    # token_expire_size.labels(env='local', group='vault')
    token_expire_size.set(stats['token_expire_size'])

    userpass_user_expire_count = Gauge('userpass_user_expire_count', 'Number of userpass_user_expire found in a backup',
                                       registry=registry)
    # userpass_user_expire_count.labels(env='local', group='vault')
    userpass_user_expire_count.set(stats['userpass_user_expire_count'])
    userpass_user_expire_size = Gauge('userpass_user_expire_size',
                                      'Size of encrypted userpass_user_expire found in a backup', registry=registry)
    # userpass_user_expire_size.labels(env='local', group='vault')
    userpass_user_expire_size.set(stats['userpass_user_expire_size'])

    push_to_gateway('localhost:9091', job='vault_backup_analyzer', registry=registry)


if __name__ == "__main__":
    backup_files = []

    for file in os.listdir("."):
        if file.endswith(".json") or file.endswith(".snap"):
            backup_files.append(os.path.join(".", file))

    total_stat = []

    for f_name in backup_files:
        total_stat.append(process_backup(f_name))

    for tot_id in range(len(total_stat)):
        pretty(total_stat[tot_id])

    push_metrics(total_stat[0])
