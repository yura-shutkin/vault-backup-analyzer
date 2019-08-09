#!/usr/bin/env bash

set -e

export VAULT_ADDR=http://localhost:8200
export HTTP_ADDR=http://localhost:8500

AUTH_BACKENDS="userpass approle ldap"
USERS="tester jester fester"
POLICY_SECRET_FULL='path "secret/*" { capabilities = ["list", "read", "update", "create", "delete"] }'
POLICY_SIMPLE_FULL='path "simple/*" { capabilities = ["list", "read", "update", "create", "delete"] }'
POLICY_TRANSIT_FULL='path "transit/*" { capabilities = ["list", "read", "update", "create", "delete"] }'
SECRETS='top lvl1/second lvl1/lvl2/third'


print_out() {
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}


print_out "login into vault"
vault login 12345

print_out "enabling policies"
echo "$POLICY_SECRET_FULL" | vault policy write secret-full -
echo "$POLICY_SIMPLE_FULL" | vault policy write simple-full -
echo "$POLICY_TRANSIT_FULL" | vault policy write transit-full -

print_out "enabling auth backends"
for auth_backend in $(echo "$AUTH_BACKENDS"); do
  vault auth enable -listing-visibility=unauth "$auth_backend"
done

print_out "enabling secrets engines"
vault secrets enable -path=simple kv
vault secrets enable -path=transit transit

print_out "create userpass users"
for vault_user in $(echo "$USERS"); do
  vault write auth/userpass/users/"$vault_user" password=12345 policies=default,secret-full,simple-full,transit-full
done

print_out "fill KVv2"
for secret in $(echo "$SECRETS"); do
  vault kv put secret/"$secret" key=val
done

print_out "fill KVv1"
for secret in $(echo "$SECRETS"); do
  vault write simple/"$secret" key=val
done

print_out "authorize userpass users"
for user in $(echo "$USERS"); do
  vault login -method=userpass username="$user" password=12345
  print_out "fill user's cubbyhole"
  for secret in $(echo "$SECRETS"); do
    vault write cubbyhole/"$secret" key=val
  done
done

print_out "revoke token"
vault token revoke -self

consul kv export vault > vault_kv.json
