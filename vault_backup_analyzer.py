import json
import sys
import hvac
import socket

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway


class Metrics:
    def __init__(self, registry, pushgateway_addr, labelnames, labelvalues):
        self.registry = registry
        self.pushgateway_addr = pushgateway_addr
        self.grouping_key = dict(zip(labelnames, labelvalues))
        self.grouping_key['instance'] = socket.gethostname()
        self.metrics = {}

    def create_metric(self, metric_name, description, labelnames):
        if metric_name not in self.metrics:
            self.metrics[metric_name] = Gauge(metric_name, description, labelnames=labelnames, registry=self.registry)

    def inc(self, metric_name, metric_labels, metric_value=1):
        self.metrics[metric_name].labels(*metric_labels).inc(metric_value)

    def push_metrics(self):
        push_to_gateway(self.pushgateway_addr, job='vault_backup_analyzer',
                        grouping_key=self.grouping_key, registry=self.registry)


def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def find_uuid_auth_backend(auth_backs, auth_type):
    for key in auth_backs.keys():
        if auth_backs[key]['type'] == auth_type:
            return key
    return None


def process_backup(backup_file_name, prom_metrics, auth_backs, secrets_engs):
    buffer = ""

    with open(backup_file_name, 'r') as backup_file:
        for piece in read_in_chunks(backup_file):
            prom_metrics, buffer = process_element(prom_metrics, buffer + piece, auth_backs, secrets_engs)
    return prom_metrics


def update_metrics(metrics_pool, m_name, m_labels, value=1, size=0):
    name = '_'.join([m_name, 'count'])
    metrics_pool.inc(name, m_labels, value)
    name = '_'.join([m_name, 'size'])
    metrics_pool.inc(name, m_labels, size)

    return metrics_pool


def process_element(prom_metrics, buffer, authbackends, secretsengines):
    def search_for_dict():
        nonlocal buffer
        dict_start = buffer.find('{')

        if 0 != dict_start:
            buffer = buffer[dict_start:]
            dict_start = buffer.find('{')
        dict_end = buffer.find('}')

        if -1 != dict_end:
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

        path = element[field].split('/')

        if 'audit' == path[1]:
            # audit_devices
            prom_metrics = update_metrics(prom_metrics, m_name='vba_system_objects', m_labels=['audit_device'], value=1,
                                          size=sys.getsizeof(element[value]))
        elif 'core' == path[1]:
            # core_objects
            prom_metrics = update_metrics(prom_metrics, m_name='vba_system_objects', m_labels=['core'], value=1,
                                          size=sys.getsizeof(element[value]))
        elif 'auth' == path[1]:
            # auth_backend_objects
            prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_objects',
                                          m_labels=[authbackends[path[2]]['type'],
                                                    authbackends[path[2]]['name']], value=1,
                                          size=sys.getsizeof(element[value]))

            if 'userpass' == authbackends[path[2]]['type']:
                if 'user' == path[3]:
                    # auth_backend_users
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_users',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

            elif 'ldap' == authbackends[path[2]]['type']:
                if 'user' == path[3]:
                    # auth_backend_users
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_users',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

                elif 'group' == path[3]:
                    # auth_backend_groups
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_groups',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

            elif 'approle' == authbackends[path[2]]['type']:
                # auth_backend_secret_ids_accessors
                if 'accessor' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_secret_ids_accessors',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

                # auth_approle_role_ids
                elif 'role_id' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_role_ids',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

                # auth_approle_secret_ids
                elif 'secret_id' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_secret_ids',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

                # auth_approle_roles
                elif 'role' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_roles',
                                                  m_labels=[authbackends[path[2]]['type'],
                                                            authbackends[path[2]]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

        elif 'logical' == path[1]:
            if 'cubbyhole' == secretsengines[path[2]]['type']:
                # auth_secrets_engine_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                              m_labels=[secretsengines[path[2]]['type'],
                                                        secretsengines[path[2]]['name'], ''], value=1,
                                              size=sys.getsizeof(element[value]))
                # auth_secrets_engine_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_secrets',
                                              m_labels=[secretsengines[path[2]]['type'],
                                                        secretsengines[path[2]]['name'], ''], value=1,
                                              size=sys.getsizeof(element[value]))

            elif 'identity' == secretsengines[path[2]]['type']:
                # auth_secrets_engine_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                              m_labels=[secretsengines[path[2]]['type'],
                                                        secretsengines[path[2]]['name'], ''], value=1,
                                              size=sys.getsizeof(element[value]))
                # auth_secrets_engine_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_secrets',
                                              m_labels=[secretsengines[path[2]]['type'],
                                                        secretsengines[path[2]]['name'], ''], value=1,
                                              size=sys.getsizeof(element[value]))

            elif 'kv' == secretsengines[path[2]]['type']:
                if 'options' in secretsengines[path[2]]:
                    # KVv2 should have version field with value equal 2. If not set - KVv1
                    if 'version' in secretsengines[path[2]]['options']:
                        if '2' == secretsengines[path[2]]['options']['version'] and len(path) > 4:
                            # auth_secrets_engine_objects
                            prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                                          m_labels=[secretsengines[path[2]]['type'],
                                                                    secretsengines[path[2]]['name'], 2], value=1,
                                                          size=sys.getsizeof(element[value]))

                            if 'metadata' == path[4]:
                                # auth_secrets_engine_secrets
                                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_secrets',
                                                              m_labels=[secretsengines[path[2]]['type'],
                                                                        secretsengines[path[2]]['name'], 2], value=1,
                                                              size=sys.getsizeof(element[value]))

                            elif 'versions' == path[4]:
                                # auth_secrets_engine_secrets_versions
                                prom_metrics = update_metrics(prom_metrics,
                                                              m_name='vba_secrets_engine_secrets_versions',
                                                              m_labels=[secretsengines[path[2]]['type'],
                                                                        secretsengines[path[2]]['name'], 2], value=1,
                                                              size=sys.getsizeof(element[value]))

                            elif 'archive' == path[4]:
                                # auth_secrets_engine_secrets_archives
                                prom_metrics = update_metrics(prom_metrics,
                                                              m_name='vba_secrets_engine_secrets_archives',
                                                              m_labels=[secretsengines[path[2]]['type'],
                                                                        secretsengines[path[2]]['name'], 2], value=1,
                                                              size=sys.getsizeof(element[value]))

                            elif 'policy' == path[4]:
                                # auth_secrets_engine_secrets_policies
                                prom_metrics = update_metrics(prom_metrics,
                                                              m_name='vba_secrets_engine_secrets_policies',
                                                              m_labels=[secretsengines[path[2]]['type'],
                                                                        secretsengines[path[2]]['name'], 2], value=1,
                                                              size=sys.getsizeof(element[value]))

                        else:
                            # auth_secrets_engine_objects
                            prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                                          m_labels=[secretsengines[path[2]]['type'],
                                                                    secretsengines[path[2]]['name'], 1], value=1,
                                                          size=sys.getsizeof(element[value]))

                            # auth_secrets_engine_secrets
                            prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_secrets',
                                                          m_labels=[secretsengines[path[2]]['type'],
                                                                    secretsengines[path[2]]['name'], 1], value=1,
                                                          size=sys.getsizeof(element[value]))

            elif 'transit' == secretsengines[path[2]]['type']:
                # secrets_engine_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                              m_labels=[secretsengines[path[2]]['type'],
                                                        secretsengines[path[2]]['name'], ''], value=1,
                                              size=sys.getsizeof(element[value]))

                if 'archive' == path[3]:
                    # secrets_engine_secrets_archives
                    prom_metrics = update_metrics(prom_metrics,
                                                  m_name='vba_secrets_engine_secrets_archives',
                                                  m_labels=[secretsengines[path[2]]['type'],
                                                            secretsengines[path[2]]['name'], 2], value=1,
                                                  size=sys.getsizeof(element[value]))

                elif 'policy' == path[3]:
                    # secrets_engine_secrets_policies
                    prom_metrics = update_metrics(prom_metrics,
                                                  m_name='vba_secrets_engine_secrets_policies',
                                                  m_labels=[secretsengines[path[2]]['type'],
                                                            secretsengines[path[2]]['name'], 2], value=1,
                                                  size=sys.getsizeof(element[value]))

        elif 'sys' == path[1]:
            if 'counters' == path[2]:
                # audit_devices
                prom_metrics = update_metrics(prom_metrics, m_name='vba_system_objects', m_labels=['counters'],
                                              value=1, size=sys.getsizeof(element[value]))

            elif 'policy' == path[2]:
                # sys_policy_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_system_objects', m_labels=['policies'],
                                              value=1, size=sys.getsizeof(element[value]))

            elif 'config' == path[2]:
                # sys_policy_objects
                prom_metrics = update_metrics(prom_metrics, m_name='vba_system_objects', m_labels=['config'],
                                              value=1, size=sys.getsizeof(element[value]))

            elif 'token' == path[2]:
                uuid = find_uuid_auth_backend(authbackends, path[2])

                prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_objects',
                                              m_labels=[authbackends[uuid]['type'],
                                                        authbackends[uuid]['name']], value=1,
                                              size=sys.getsizeof(element[value]))

                if 'accessor' == path[3]:
                    # auth_backend_users
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_token_accessors',
                                                  m_labels=[authbackends[uuid]['type'],
                                                            authbackends[uuid]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

                elif 'id' == path[3]:
                    # auth_backend_users
                    prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_tokens',
                                                  m_labels=[authbackends[uuid]['type'],
                                                            authbackends[uuid]['name']], value=1,
                                                  size=sys.getsizeof(element[value]))

            elif 'expire' == path[2]:
                if 'id' == path[3]:
                    if 'auth' == path[4]:
                        uuid = find_uuid_auth_backend(authbackends, path[5])

                        if 'login' == path[6]:
                            # auth_backend_tokens
                            prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_tokens',
                                                          m_labels=[authbackends[uuid]['type'],
                                                                    authbackends[uuid]['name']], value=1,
                                                          size=sys.getsizeof(element[value]))

                        elif 'renew-self' == path[6]:
                            prom_metrics = update_metrics(prom_metrics, m_name='vba_auth_backend_token_renew_self',
                                                          m_labels=[authbackends[uuid]['type'],
                                                                    authbackends[uuid]['name']], value=1,
                                                          size=sys.getsizeof(element[value]))

                    else:
                        # auth_secrets_engine_objects
                        prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_objects',
                                                      m_labels=[path[4],
                                                                'expire', ''], value=1,
                                                      size=sys.getsizeof(element[value]))
                        # auth_secrets_engine_objects
                        prom_metrics = update_metrics(prom_metrics, m_name='vba_secrets_engine_secrets',
                                                      m_labels=[path[4],
                                                                'expire', ''], value=1,
                                                      size=sys.getsizeof(element[value]))

        element = search_for_dict()

    return prom_metrics, buffer


def convert_hvac_dict(response_dict):
    processed_dict = {}
    for item in response_dict['data'].keys():
        processed_dict[response_dict[item]['uuid']] = response_dict[item]
        processed_dict[response_dict[item]['uuid']]['name'] = item.strip('/')
        del processed_dict[response_dict[item]['uuid']]['uuid']

    return processed_dict


if __name__ == "__main__":
    # TODO: args should be parsed in separated function
    BACKUP_FNAME = sys.argv[1]
    # TODO: variability:
    #    Should script push metrics to pushgateway or
    #      * start it's own web server
    #      * just output metrics to log
    PUSHGATEWAY_ADDR = sys.argv[2]
    LABELS = sys.argv[3]
    # TODO: variability:
    #  WIth query to vault and without
    #  Use vault agent for get and store token to file
    #  If we don't want convert UUIDs to human readable values
    #  Also It is possible that script will read data with unknown IDs
    VAULT_ADDR = sys.argv[4]
    VAULT_CREDS_FILE = sys.argv[5]

    labels = LABELS.split(',')
    label_names = []
    label_values = []

    for label in labels:
        label_name, label_value = label.split('=')
        label_names.append(label_name)
        label_values.append(label_value)

    with open(VAULT_CREDS_FILE, 'r') as creds_file:
        creds = json.loads(creds_file.read())

    VAULT_ROLE_ID = creds['role_id']
    VAULT_SECRET_ID = creds['secret_id']

    vault_client = hvac.Client(url=VAULT_ADDR, verify=True)
    vault_token = vault_client.auth_approle(VAULT_ROLE_ID, VAULT_SECRET_ID)

    auth_backends = convert_hvac_dict(vault_client.sys.list_auth_methods())
    secrets_engines = convert_hvac_dict(vault_client.sys.list_mounted_secrets_engines())

    prom_registry = CollectorRegistry()
    # Init metrics
    metrics = Metrics(registry=prom_registry, pushgateway_addr=PUSHGATEWAY_ADDR, labelnames=label_names,
                      labelvalues=label_values)

    metrics_list = {
        'vba_auth_backend_objects_count': {'label_names': ['type', 'mount_point'],
                                           'description': 'Count auth backend objects'},
        'vba_auth_backend_objects_size': {'label_names': ['type', 'mount_point'],
                                          'description': 'Size of auth backend objects'},
        'vba_auth_backend_roles_count': {'label_names': ['type', 'mount_point'],
                                         'description': 'Count auth backend roles'},
        'vba_auth_backend_roles_size': {'label_names': ['type', 'mount_point'],
                                        'description': 'Size of auth backend role_ids'},
        'vba_auth_backend_role_ids_count': {'label_names': ['type', 'mount_point'],
                                            'description': 'Count auth backend role_ids'},
        'vba_auth_backend_role_ids_size': {'label_names': ['type', 'mount_point'],
                                           'description': 'Size of auth backend roles'},
        'vba_auth_backend_secret_ids_count': {'label_names': ['type', 'mount_point'],
                                              'description': 'Count auth backend secret_ids'},
        'vba_auth_backend_secret_ids_size': {'label_names': ['type', 'mount_point'],
                                             'description': 'Size of auth backend secret_ids'},
        'vba_auth_backend_secret_ids_accessors_count': {'label_names': ['type', 'mount_point'],
                                                        'description': 'Count auth backend secret_ids_accessors'},
        'vba_auth_backend_secret_ids_accessors_size': {'label_names': ['type', 'mount_point'],
                                                       'description': 'Size of auth backend secret_ids_accessors'},
        'vba_auth_backend_tokens_count': {'label_names': ['type', 'mount_point'],
                                          'description': 'Count auth backend tokens'},
        'vba_auth_backend_tokens_size': {'label_names': ['type', 'mount_point'],
                                         'description': 'Size of auth backend tokens'},
        'vba_auth_backend_token_renew_self_count': {'label_names': ['type', 'mount_point'],
                                                     'description': 'Count auth backend tokens renew self'},
        'vba_auth_backend_token_renew_self_size': {'label_names': ['type', 'mount_point'],
                                                    'description': 'Size of auth backend tokens renew self'},
        'vba_auth_backend_token_accessors_count': {'label_names': ['type', 'mount_point'],
                                                   'description': 'Count auth backend token accessors'},
        'vba_auth_backend_token_accessors_size': {'label_names': ['type', 'mount_point'],
                                                  'description': 'Size of auth backend token accessors'},
        'vba_auth_backend_users_count': {'label_names': ['type', 'mount_point'],
                                         'description': 'Count auth backend users'},
        'vba_auth_backend_users_size': {'label_names': ['type', 'mount_point'],
                                        'description': 'Size of auth backend users'},
        'vba_auth_backend_groups_count': {'label_names': ['type', 'mount_point'],
                                          'description': 'Count auth backend groups'},
        'vba_auth_backend_groups_size': {'label_names': ['type', 'mount_point'],
                                         'description': 'Size of auth backend groups'},
        'vba_secrets_engine_objects_count': {'label_names': ['type', 'mount_point', 'version'],
                                             'description': 'Count secrets engine objects'},
        'vba_secrets_engine_objects_size': {'label_names': ['type', 'mount_point', 'version'],
                                            'description': 'Size of secrets engine objects'},
        'vba_secrets_engine_secrets_count': {'label_names': ['type', 'mount_point', 'version'],
                                             'description': 'Count secrets engine secrets'},
        'vba_secrets_engine_secrets_size': {'label_names': ['type', 'mount_point', 'version'],
                                            'description': 'Size of secrets engine secrets'},
        'vba_secrets_engine_secrets_archives_count': {'label_names': ['type', 'mount_point', 'version'],
                                                      'description': 'Count secrets engine secrets archives'},
        'vba_secrets_engine_secrets_archives_size': {'label_names': ['type', 'mount_point', 'version'],
                                                     'description': 'Count secrets engine secrets archives'},
        'vba_secrets_engine_secrets_policies_count': {'label_names': ['type', 'mount_point', 'version'],
                                                      'description': 'Count secrets engine secrets policies'},
        'vba_secrets_engine_secrets_policies_size': {'label_names': ['type', 'mount_point', 'version'],
                                                     'description': 'Count secrets engine secrets policies'},
        'vba_secrets_engine_secrets_versions_count': {'label_names': ['type', 'mount_point', 'version'],
                                                      'description': 'Count secrets engine secrets versions'},
        'vba_secrets_engine_secrets_versions_size': {'label_names': ['type', 'mount_point', 'version'],
                                                     'description': 'Count secrets engine secrets versions'},
        'vba_system_objects_count': {'label_names': ['type'], 'description': 'Count system objects'},
        'vba_system_objects_size': {'label_names': ['type'], 'description': 'Size of system objects'},
    }

    for metric in metrics_list.keys():
        metrics.create_metric(metric_name=metric, description=metrics_list[metric]['description'],
                              labelnames=metrics_list[metric]['label_names'])

    metrics = process_backup(BACKUP_FNAME, metrics, auth_backends, secrets_engines)

    metrics.push_metrics()
