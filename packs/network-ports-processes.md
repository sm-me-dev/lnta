---
id: network-ports-processes
name: Network Ports and Processes
triggers:
  - port
  - listening
  - ss -tulpn
  - lsof
  - network port
  - what is using port
allowed_paths: []
required_bins:
  - ss
context_cmd: ss --version
verify_cmd: ss -tulpn | grep "${port}"
---
# Network Ports and Processes

Read-only diagnostics for listening ports and the processes that own them.

## What this pack covers
- Listing listening TCP/UDP sockets with `ss -tulpn` (or `lsof -i` as fallback).
- Mapping a listening port to its PID and process name.
- Identifying which process is bound to a specific port.
- Checking for unexpected or unexpected listeners.

## Safety
This pack is read-only. It never starts, stops, or modifies processes or
services. Use `ss`/`lsof` diagnostics only.
