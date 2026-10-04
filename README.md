# Threat Hunt: Brute-Force Attack on Internet-Facing Windows Hosts

**Platform:** Microsoft Sentinel · KQL · Windows Security Events
**Domain:** Threat Hunting · Credential access · Attack-surface hardening
**Detection surface:** Microsoft Sentinel (Defender portal) — `SecurityEvent`

---

## The problem — a real-world attack, not a hypothetical

Internet-exposed remote-access services are among the most relentlessly attacked targets on the internet, and a primary entry vector for ransomware. The **2021 Colonial Pipeline** incident — which shut down the largest fuel pipeline in the US and triggered panic fuel-buying across the East Coast — began with a **single compromised remote-access credential** on an account that lacked MFA. More broadly, the DarkSide, Phobos, and Dharma ransomware families have all used exposed remote access and credential guessing as a routine foothold. [1][2]

Attackers scan the internet continuously for exposed login services, then spray them with automated dictionaries of common usernames and passwords. The volume is enormous and the signal is simple — a flood of failed logons — but the analyst's job is not just to *see* the flood. It is to answer the question that sets severity: **did any of it succeed?** A thousand failures is noise; one success buried among them is a breach.

## What this project is — and the skills it proves

This project is a **threat hunt across Windows security telemetry** that detects a large-scale brute-force campaign, identifies the targeted assets, and — critically — verifies whether the attack succeeded, correctly filtering out benign system activity that a less careful analyst would misread as a compromise. It then delivers root-cause hardening recommendations aimed at the exposed asset, since the attacker's source could not be blocked.

| Real-world failure | Capability this project builds |
|---|---|
| Exposed login services are sprayed continuously and go unnoticed | Detect brute-force floods via failed-logon aggregation |
| Analyst reports a flood but never checks if it worked | Success/failure verification that sets true severity |
| Benign `SYSTEM` logons mistaken for intrusions | Built-in vs. malicious account triage to avoid false escalations |
| No source IP to block leaves the team feeling helpless | Pivot to root-cause hardening of the victim asset |

---

## Scenario & hypothesis

An attacker who does not already hold valid credentials will attempt to guess them — firing large volumes of password attempts against an account. This produces a distinctive fingerprint: a high count of **failed logons** against one or more accounts in a short period.

**Hypothesis:** Accounts with an abnormally high number of failed logons are candidates for an active brute-force attack.

**Key concept — Windows logon Event IDs:** unlike Okta's text-based result field, Windows encodes logon outcomes numerically:
- `4625` = failed logon
- `4624` = successful logon

---

## Hunt methodology

### Step 1 — Surface the failed-logon pile

Count failed logons per account to find who is being hammered.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogin = count() by Account
| order by FailedLogin desc
```

**Result (top rows):**

| Account | FailedLogin |
|---|---|
| \ADMINISTRATOR | 10,255 |
| \admin | 1,989 |
| \administrator | 1,864 |
| \ADMIN | 598 |
| \USER, \TEST, \SERVER … | hundreds each |
| \ADMINISTRADOR, \ADMINISTRATEUR | tens each |

The pattern itself is diagnostic. The list is dominated by **common default usernames** and **localised admin names** (`ADMINISTRADOR` – Spanish, `ADMINISTRATEUR` – French). A human would not guess these; an automated tool with a built-in wordlist would. This is a **dictionary spray** — the attacker is guessing both usernames *and* passwords, so most of these accounts likely do not even exist on the target. A failed logon is recorded regardless of whether the account exists.

![Failed logon pile dominated by default and foreign-language admin names](5.png)

### Step 2 — Add the target asset

Grouping by `Computer` reveals *what* is under attack.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogin = count() by Account, Computer
| order by FailedLogin desc
```

**Result:** failures cluster on two hosts:
- **`SOC-FW-RDP`** — `ADMINISTRATOR` alone hit 9,997 times, plus `ADMIN`, `USER`, `TEST`, `SERVER`, and foreign-language admin variants.
- **`SHIR-Hive`** — `admin` / `administrator` hammered ~2,000+ times each.

The host naming and the attack shape (high-volume failed logons against default admin accounts on internet-facing hosts) point to an exposed remote-access service as the target. To confirm the exact logon channel — for example RDP (RemoteInteractive) versus network logon — the hunt would filter on the `LogonType` field (`LogonType == 10` indicates RemoteInteractive/RDP). Absent that confirmation, the finding is stated as a brute-force attack against internet-facing hosts rather than asserting a specific protocol.

**Source limitation:** `IpAddress` was empty for the attack rows. On certain Windows `4625` logon types the source IP is not populated in `IpAddress`, and may appear in alternate fields (`WorkstationName`, `ClientAddress`). This left the attacker's source unidentified — an important gap for response, and a logging improvement to flag.

### Step 3 — The severity-defining question: did it succeed?

Failures alone mean the attacker knocked but may not have entered. I pivoted to successful logons (`4624`) on the affected hosts.

```kql
SecurityEvent
| where EventID == 4624
| summarize SuccessfulLogin = count() by Account, Computer
| order by SuccessfulLogin desc
```

**Result on the attacked hosts:**
- `SOC-FW-RDP` → only `NT AUTHORITY\SYSTEM` (10)
- `SHIR-Hive` → only `NT AUTHORITY\SYSTEM` (4)

**No `administrator`, no `admin`, no attacker-guessed account succeeded.**

![Successful logon check — only NT AUTHORITY SYSTEM succeeded on the attacked hosts](6.png)

---

## Findings & analysis

**The brute force failed.** No targeted account achieved a successful logon on either host.

**Critical read — filtering out built-in accounts:** the only "successes" on the attacked hosts were `NT AUTHORITY\SYSTEM`. This is **not a user or an attacker** — it is the local machine/OS account, which logs on continuously as part of normal Windows operation. Treating a `SYSTEM` logon as an intrusion is a common false-alarm; recognising built-in and service accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, and machine accounts ending in `$` such as `ADMINPC2$`) as benign is essential to avoid crying wolf.

The remaining successful logons elsewhere (`CONTOSO\SamiraA`, `CONTOSO\RonHD`, `AATPService`) are legitimate domain activity on other machines, unrelated to the attack.

**Verdict:** True positive, **unsuccessful** brute-force attack against `SOC-FW-RDP` and `SHIR-Hive`. No compromise occurred, but the hosts are exposed and under continuous attack.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110.001 – Brute Force: Password Guessing | 10,000+ failed logons against default account names |
| Credential Access | T1110.003 – Brute Force: Password Spraying | Wide spread of guessed usernames across hosts |
| Initial Access | T1133 – External Remote Services | Internet-facing host targeted as the entry point |

---

## Response & hardening

The attacker's source could not be blocked (no source IP captured), so the response is root-cause focused — removing the conditions that let the attack happen at all:

1. **Remove the exposed service from direct internet exposure** — the root fix. Place remote access behind a VPN or bastion/jump host, or restrict it to known admin source IPs. If the service is unreachable from the open internet, the attack never begins.
2. **Enforce an account lockout policy** — lock accounts after a small number of failed attempts (e.g. 5) for a set duration. This makes high-volume guessing mechanically impossible without needing to identify the attacker. *Caveat:* lockout can be abused for denial-of-service (deliberately locking legitimate users), so pair it with monitoring rather than treating it as a complete solution.
3. **Enforce MFA** on remote-access accounts so a correct password guess alone is insufficient to authenticate — the control whose absence enabled the Colonial Pipeline breach.
4. **Improve logging** to reliably capture the source and logon type of `4625` events (workstation/IP, `LogonType`), removing the blind spot that prevented source attribution and protocol confirmation in this investigation.

---

## Key design decisions

- **A failed attack is still a true positive.** "True positive, unsuccessful" ≠ "false positive" — the detection was correct; the attack simply did not work. Reporting it accurately matters for metrics and for recognising a host that *will* eventually be breached if left exposed.
- **Verify success before declaring severity.** The hunt does not stop at "there is a flood"; it pivots to `4624` to answer whether anything got in — the single fact that separates noise from breach.
- **State what the data proves, not what it suggests.** The attack is characterised as brute-force against internet-facing hosts; the specific protocol (e.g. RDP) is called out as something to confirm via `LogonType`, not asserted from host naming alone.
- **Know your built-in accounts.** `SYSTEM` and machine (`$`) accounts logging on successfully is normal; recognising them as benign prevents false escalations.
- **"Field is empty" ≠ "data doesn't exist."** A blank `IpAddress` is a prompt to look in alternate columns, not a dead end.
- **When you can't fix the attacker, harden the victim.** With no source IP to block, the response targets the exposed asset — the only thing within the defender's control.

---

## Future improvements

- **Confirm the logon channel** — add `where LogonType == 10` to establish whether the brute force came over RDP specifically, rather than inferring it from host naming.
- **Operationalise as an analytics rule** — a scheduled Sentinel rule firing on a failed-logon threshold per host/hour, with the threshold tuned against the observed false-positive rate.
- **Enrich source attribution** — parse `WorkstationName`/`ClientAddress` so future detections capture the attacker's origin even when `IpAddress` is blank.
- **Correlate failure-then-success** — a time-windowed rule that specifically flags a successful logon immediately following a failure burst on the same account/host, catching the moment a spray actually lands.

---

## Skills demonstrated

Threat hunting with KQL · Windows Event ID analysis (4624/4625) · Attack-pattern recognition · Success/failure verification · Built-in vs. malicious account triage · Evidence-based classification · Root-cause hardening recommendations · MITRE ATT&CK mapping

---

## References

1. CISA — [DarkSide Ransomware: Best Practices for Preventing Business Disruption (AA21-131A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a) — Colonial Pipeline, compromised remote-access credential without MFA (May 2021).
2. CISA / FBI — [#StopRansomware: Phobos Ransomware (AA24-060A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a) — exposed remote access and credential guessing as a primary initial-access vector.
