# Threat Model: SSO Bypass vs Firmware Evasion

## Threat 1: OAuth State CSRF
- **Vector:** The `/user/oauth2/:provider/callback` endpoint fails to match the `State` cookie cryptographically.
- **Impact:** Attackers bind their own OAuth identity to an active admin's session.
- **Defense:** Strict cryptographic state checks in `routers/routes.go`.

## Threat 2: RAM Scraping via SMM (Ring-2)
- **Vector:** UEFI Bootkit utilizes Direct Memory Access (DMA) to scrape plaintext `SessionID` tokens directly from the RAM pages hosting the Gitea container process.
- **Impact:** Total bypass of all 2FA, MFA, and SSO logic. The attacker steals an active session token natively.
- **Defense:** Extremely difficult. Requires hardware-level attestation (Intel Boot Guard, TPM 2.0 Secure Boot with custom DB/DBX, and measured boot architectures).
