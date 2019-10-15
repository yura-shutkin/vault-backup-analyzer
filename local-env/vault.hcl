storage "consul" {
  address = "consul:8500"
  path = "vault/"
  scheme = "http"
  service_tags = "vault-local"
  service_address = "vault-local-node"
}

telemetry {
  disable_hostname = true
  prometheus_retention_time = "1h"
}

log_level = "Info"
