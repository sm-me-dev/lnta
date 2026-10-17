---
id: network-ports-processes
name: Network Ports and Processes
triggers:
  - port
  - listening
  - network port
allowed_paths: []
required_bins:
  - ss
context_cmd: ss --version
verify_cmd: ss -tulpn | grep "${port}"
---
# Network Ports and Processes (test)

Read-only port diagnostics.
