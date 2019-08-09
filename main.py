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
        self.metrics = {
            'total_metrics': Gauge('total_metrics', 'Metrics total from vault backup', registry=self.registry)}
        self.metrics['total_metrics'].set(1)

    def inc(self, metric_name, metric_description, metric_value=1, metric_type='gauge'):
        if metric_name not in self.metrics:
            if 'gauge' == metric_type:
                self.metrics[metric_name] = Gauge(metric_name, metric_description, registry=self.registry)
                self.metrics[metric_name].set(metric_value)
                self.metrics['total_metrics'].inc()
        else:
            if isinstance(self.metrics[metric_name], Gauge):
                self.metrics[metric_name].inc(metric_value)

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


def process_backup(backup_file_name, metrics, auth_backends, secrets_engines):
    buffer = ""

    with open(backup_file_name, 'r') as backup_file:
        for piece in read_in_chunks(backup_file):
            metrics, buffer = process_element(metrics, buffer + piece, auth_backends, secrets_engines)
    return metrics


def update_metrics(metrics_pool, prefix, name, m_type='objects', value=1, size=0):
    def inc_metric(postfix, val):
        # <prefix>_<name>_count
        # <prefix>_<name>_size
        # auth_approle_count
        # auth_approle_size
        # auth_approle_secret_id_count
        # auth_approle_secret_size
        # secrets_kv-project_count
        # secrets_kv-project_size
        # secrets_kv-project_secrets_count
        # secrets_kv-project_secrets_size
        # secrets_kv-project_versions_count
        # secrets_kv-project_versions_size
        # audit_devices_count
        # audit_devices_size
        m_name = '_'.join((prefix, name, postfix))
        # Ensure all dashes replased with ground
        m_name = m_name.replace('-', '_')
        # Ensure all slashes replased with ground
        m_name = m_name.replace('/', '_')

        metrics_pool.inc(m_name, description, val)

    # Total <m_type> count in <name>
    # Total size of <m_type> in <name>
    # Total versions count in project_1234_secrets
    # Total objects count in core
    # Total roles count in auth_kubernetes
    description = 'Total {} count in {}'.format(m_type, name)
    inc_metric('count', value)

    description = 'Total size of {} in {}'.format(m_type, name)
    inc_metric('size', size)

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

        # objects_total_devices
        prom_metrics = update_metrics(prom_metrics, 'objects', 'total', 'objects', value=1,
                                      size=sys.getsizeof(element[value]))

        if 'audit' == path[1]:
            # audit_devices
            prom_metrics = update_metrics(prom_metrics, path[1], 'objects', 'devices', value=1,
                                          size=sys.getsizeof(element[value]))
        elif 'core' == path[1]:
            # core_objects
            prom_metrics = update_metrics(prom_metrics, path[1], 'objects', 'objects', value=1,
                                          size=sys.getsizeof(element[value]))
        elif 'auth' == path[1]:
            # auth_objects
            prom_metrics = update_metrics(prom_metrics, path[1], 'objects', 'objects', value=1,
                                          size=sys.getsizeof(element[value]))

            if 'userpass' == authbackends[path[2]]['type']:
                # auth_<auth_backend>_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                if 'user' == path[3]:
                    # auth_userpass_users
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'users', 'users', value=1, size=sys.getsizeof(element[value]))

                else:
                    # auth_userpass_unknown_objects
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'unknown_objects', 'unknown objects', value=1,
                                                  size=sys.getsizeof(element[value]))
                    # for debug
                    print(authbackends[path[2]]['name'], path)

            elif 'ldap' == authbackends[path[2]]['type']:
                # auth_ldap_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                if 'user' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  path[3], value=1, size=sys.getsizeof(element[value]))

                elif 'group' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  path[3], value=1, size=sys.getsizeof(element[value]))

                elif path[3] in ['config', 'salt']:
                    # already counted
                    pass

                else:
                    # auth_ldap_unknown_objects
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'unknown_objects', 'unknown objects', value=1,
                                                  size=sys.getsizeof(element[value]))
                    # for debug
                    print(authbackends[path[2]]['name'], path)

            elif 'approle' == authbackends[path[2]]['type']:
                # auth_approle_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                # auth_approle_secret_id_accessors
                if 'accessor' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'secret_id_accessors', 'secret-id accessors',
                                                  value=1, size=sys.getsizeof(element[value]))

                # auth_approle_role_ids
                elif 'role_id' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'role_ids', 'role_ids',
                                                  value=1, size=sys.getsizeof(element[value]))

                # auth_approle_secret_ids
                elif 'secret_id' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'secret_ids', 'secret_ids',
                                                  value=1, size=sys.getsizeof(element[value]))

                # auth_approle_roles
                elif 'role' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'approles', 'approles',
                                                  value=1, size=sys.getsizeof(element[value]))

                elif path[3] in ['config', 'salt']:
                    # already counted
                    pass

                else:
                    # auth_approle_unknown_objects
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                                  'unknown_objects', 'unknown objects', value=1,
                                                  size=sys.getsizeof(element[value]))
                    # for debug
                    print(authbackends[path[2]]['name'], path)
            # TODO: token can't find if it can be stored in to <auth>
            elif 'token' == authbackends[path[2]]['type']:
                # auth_token_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], authbackends[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))
            else:
                # auth_unknown_objects
                prom_metrics = update_metrics(prom_metrics, path[1], 'unknown_objects', 'unknown objects', value=1,
                                              size=sys.getsizeof(element[value]))
                # for debug
                print(authbackends[path[2]]['name'], path)

        elif 'logical' == path[1]:
            # logical_objects
            prom_metrics = update_metrics(prom_metrics, path[1], 'objects', 'objects', value=1,
                                          size=sys.getsizeof(element[value]))

            if 'cubbyhole' == secretsengines[path[2]]['type']:
                # logical_cubbyhole_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

            elif 'identity' == secretsengines[path[2]]['type']:
                # logical_identity_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

            elif 'kv' == secretsengines[path[2]]['type']:
                # KVv2 should have version field with value equal 2. If not set - KVv1
                if 'version' in secretsengines[path[2]]['options']:
                    if '2' == secretsengines[path[2]]['options']['version'] and len(path) > 4:
                        # logical_<kv_name>_objects
                        prom_metrics = update_metrics(prom_metrics,
                                                      '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                      'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                        # logical_<kv_name>_archive
                        if 'archive' == path[4]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                          path[4], 'objects',
                                                          value=1, size=sys.getsizeof(element[value]))

                        # logical_<kv_name>_policy
                        elif 'policy' == path[4]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                          path[4], 'objects',
                                                          value=1, size=sys.getsizeof(element[value]))

                        # logical_<kv_name>_secrets
                        elif 'metadata' == path[4]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                          'secrets', 'secrets',
                                                          value=1, size=sys.getsizeof(element[value]))

                        # logical_<kv_name>_versions
                        elif 'versions' == path[4]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                          'versions', 'versions',
                                                          value=1, size=sys.getsizeof(element[value]))

                        elif path[4] in ['config', 'salt', 'upgrading']:
                            # already counted
                            pass

                        else:
                            # logical_<kv_name>_unknown_objects
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                          'unknown_objects', 'unknown objects', value=1,
                                                          size=sys.getsizeof(element[value]))
                            # for debug
                            print(secretsengines[path[2]]['name'], 'kvv2', path)
                    else:
                        # TODO: duplication
                        # logical_<kv_name>_secrets
                        prom_metrics = update_metrics(prom_metrics,
                                                      '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                      'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                        # logical_<kv_name>_secrets
                        prom_metrics = update_metrics(prom_metrics,
                                                      '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                      'secrets', 'secrets', value=1, size=sys.getsizeof(element[value]))
                else:
                    # logical_<kv_name>_secrets
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                  'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                    # logical_<kv_name>_secrets
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                  'secrets', 'secrets', value=1, size=sys.getsizeof(element[value]))

            elif 'transit' == secretsengines[path[2]]['type']:
                # logical_<transit_name>_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                              'objects', 'objects', value=1, size=sys.getsizeof(element[value]))

                # logical_<transit_name>_archive
                if 'archive' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                  path[3], 'archives', value=1, size=sys.getsizeof(element[value]))

                # logical_<transit_name>_policy
                elif 'policy' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                  path[3], 'policies', value=1, size=sys.getsizeof(element[value]))

                else:
                    # logical_<transit_name>_unknown_objects
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                                  'unknown_objects', 'unknown objects', value=1,
                                                  size=sys.getsizeof(element[value]))
                    print(secretsengines[path[2]]['name'], path)
            else:
                # logical_unknown_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], secretsengines[path[2]]['name'])),
                                              'unknown_objects', 'unknown objects', value=1,
                                              size=sys.getsizeof(element[value]))
                # for debug
                print(secretsengines[path[2]]['name'], path)
        elif 'sys' == path[1]:
            # sys_objects
            prom_metrics = update_metrics(prom_metrics, path[1], 'objects', 'objects', value=1,
                                          size=sys.getsizeof(element[value]))

            if 'counters' == path[2]:
                # sys_counters_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'objects', 'objects', value=1,
                                              size=sys.getsizeof(element[value]))

            elif 'expire' == path[2]:
                # sys_expire_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'objects', 'objects', value=1,
                                              size=sys.getsizeof(element[value]))

                # sys_expire_id
                if 'id' == path[3]:
                    # will not count. Probably unnecessary statistic

                    if 'auth' == path[4]:
                        # sys_expire_<path[4]>_<path[5]>_<path[6]>
                        # sys_expire_auth_<auth_backend>_{login|renew-self}
                        if 'login' == path[6]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], path[2], path[4], path[5])), 'logins',
                                                          'logins', value=1, size=sys.getsizeof(element[value]))

                        elif 'renew-self' == path[6]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], path[2], path[4], path[5])),
                                                          'tokens_renewed', 'tokens renewed', value=1,
                                                          size=sys.getsizeof(element[value]))

                        else:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], path[2], path[4])), 'unknown_objects',
                                                          'unknown objects', value=1,
                                                          size=sys.getsizeof(element[value]))
                            # for debug
                            print(path[4], path[6], path)

                    elif 'sys' == path[4]:
                        # sys_expire_wrapped_objects
                        if 'wrap' == path[6]:
                            prom_metrics = update_metrics(prom_metrics,
                                                          '_'.join((path[1], path[2])), 'wrapped_objects',
                                                          '_'.join(('wrapped', 'objects')), value=1,
                                                          size=sys.getsizeof(element[value]))

                    elif path[4] in ['config', 'salt', 'upgrading']:
                        # already counted
                        pass

                    else:
                        # sys_expire_unknown_objects
                        prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])),
                                                      'unknown_objects', 'unknown objects', value=1,
                                                      size=sys.getsizeof(element[value]))
                        # for debug
                        print(path[2], path)

            elif 'policy' == path[2]:
                # sys_policy_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'objects', 'objects', value=1,
                                              size=sys.getsizeof(element[value]))

            elif 'token' == path[2]:
                # sys_token_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'objects', 'objects', value=1,
                                              size=sys.getsizeof(element[value]))

                # sys_token_accessors
                if 'accessor' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'accessors', 'accessors',
                                                  value=1, size=sys.getsizeof(element[value]))

                # sys_token_ids
                elif 'id' == path[3]:
                    prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'ids', 'ids',
                                                  value=1, size=sys.getsizeof(element[value]))

            elif 'config' == path[2]:
                # sys_config_objects
                prom_metrics = update_metrics(prom_metrics, '_'.join((path[1], path[2])), 'objects', 'objects', value=1,
                                              size=sys.getsizeof(element[value]))

            else:
                # sys_unknown_objects
                prom_metrics = update_metrics(prom_metrics, path[1], 'unknown_objects', 'unknown objects', value=1,
                                              size=sys.getsizeof(element[value]))
                print(path[2], path)
        else:
            # <unknown_branch>_unknown_objects
            prom_metrics = update_metrics(prom_metrics, path[1], 'unknown_objects', 'unknown objects', value=1,
                                          size=sys.getsizeof(element[value]))
            print(path[1], path)

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
    VAULT_ROLE_ID = sys.argv[5]
    VAULT_SECRET_ID = sys.argv[6]

    labels = LABELS.split(',')
    label_names = []
    label_values = []

    for label in labels:
        label_name, label_value = label.split('=')
        label_names.append(label_name)
        label_values.append(label_value)

    vault_client = hvac.Client(url=VAULT_ADDR, verify=True)
    vault_token = vault_client.auth_approle(VAULT_ROLE_ID, VAULT_SECRET_ID)

    auth_backends = convert_hvac_dict(vault_client.sys.list_auth_methods())
    secrets_engines = convert_hvac_dict(vault_client.sys.list_mounted_secrets_engines())

    prom_registry = CollectorRegistry()
    metrics = Metrics(registry=prom_registry, pushgateway_addr=PUSHGATEWAY_ADDR, labelnames=label_names,
                      labelvalues=label_values)

    for auth_backend in auth_backends:
        metrics = update_metrics(metrics, '_'.join(('auth', auth_backends[auth_backend]['name'])),
                                 'objects', value=0, size=0)

    metrics = process_backup(BACKUP_FNAME, metrics, auth_backends, secrets_engines)

    metrics.push_metrics()
