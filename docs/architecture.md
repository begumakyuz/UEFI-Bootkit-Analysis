# Gitea & UEFI Bootkit Architecture

This document describes the layered architecture of the Gitea code base and the UEFI Ring-2 execution mapping.

## 1. Top Level: Gitea OS Isolation
Gitea is executed locally in a rootless docker environment `USER 1000:1000`. This prevents basic container escapes.

## 2. CI/CD & Database Spin-ups
GitHub Actions dynamically spin up PostgreSQL/MySQL instances upon a push. The `services:` block strictly isolates the network traffic between the runner and the DB container.

## 3. The EFI Firmware Vector (BlackLotus)
Despite OS-level hardening, a malicious `.efi` payload planted in the EFI System Partition (ESP) will be executed by the Motherboard's boot manager *before* the Windows/Linux Kernel is loaded. This grants the payload SMM (System Management Mode) powers, invalidating Docker's Ring-3 isolation entirely.

### Boot Sequence Hooking:
- Motherboard Power-On -> POST
- SEC -> PEI -> DXE (Bootkit Loaded Here)
- Bootkit hooks `ExitBootServices`.
- OS Kernel loads, but Bootkit maintains read/write access to OS RAM dynamically.
