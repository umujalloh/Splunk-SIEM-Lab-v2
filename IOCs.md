# Indicators of Compromise (IOCs)

## Analyst: Umu Jalloh
## Investigation: Frothly CoinMiner Drive-By Attack
## Date: 2018-08-20

 
This document lists all indicators of compromise identified during the BOTSv3 CoinMiner investigation. These IOCs can be used for hunting similar threats in other environments.
 
---
 
## Network Indicators
 
### Malicious Domains
 
| Domain | Type | Description | Source Query |
|---|---|---|---|
| `coinhive.com` | C2 / Mining Pool | CoinHive cryptocurrency mining infrastructure used to coordinate Monero mining operations | Q10, Q11 |
 
### Compromised Legitimate Sites
 
| Domain | Type | Description | Source Query |
|---|---|---|---|
| `www.brewertalk.com` | Compromised Forum | Brewing community forum with site-wide JSCoinminer JavaScript injection | Q08, Q12, Q13 |
 
### Specific Compromised URLs
 
The following 10 brewertalk URLs served the malicious JSCoinminer script (Q13):
 
| URL | Description |
|---|---|
| `www.brewertalk.com/` | Forum homepage |
| `www.brewertalk.com/index.php` | Index page |
| `www.brewertalk.com/forumdisplay.php?fid=5` | Forum category |
| `www.brewertalk.com/forumdisplay.php?fid=7` | Forum category |
| `www.brewertalk.com/forumdisplay.php?fid=8` | Forum category |
| `www.brewertalk.com/forumdisplay.php?fid=9` | Forum category |
| `www.brewertalk.com/forumdisplay.php?fid=11` | Forum category |
| `www.brewertalk.com/showthread.php?tid=22` | Forum thread |
| `www.brewertalk.com/attachment.php?thumbnail=2` | Attachment |
| `www.brewertalk.com/attachment.php?thumbnail=9` | Attachment |
 
The breadth of affected pages indicates a site-wide compromise of brewertalk, not isolated page injection.
 
---
 
## Malware Indicators
 
### Malware Family
 
| Name | Type | Description |
|---|---|---|
| **JSCoinminer** | JavaScript Cryptominer | Browser-based Monero cryptocurrency miner that hijacks visitor CPU resources |
 
### Symantec Detection Signatures
 
| Signature ID | Signature String | Action |
|---|---|---|
| **30356** | Web Attack: JSCoinminer Download 6 | Blocked |
| **30358** | Web Attack: JSCoinminer Download 8 | Blocked |
| Sub-ID **70471** | (Variant of 30356) | Blocked |
| Sub-ID **70481** | (Variant of 30358) | Blocked |
 
### File Hashes (from Symantec logs)
 
| Hash Type | Value |
|---|---|
| SHA-256 | `268A0463D7CB907D45E1C2AB91703E71734116F08B2C090E34C2D506183F9BCA` |
| SHA-256 | `42D2F666AFD8A350A3F3BBCD736D7E35543D9DD9753B211C9F03C4F7E669ACE3` |
 
---
 
## Host Indicators
 
### Affected Host (Successful Compromise)
 
| Hostname | IP | OS | User | Browser | Outcome |
|---|---|---|---|---|---|
| **BSTOLL-L** | (not captured) | Windows | bstoll | Chrome | Mining succeeded - sustained 100% CPU for 26 minutes |
 
### Protected Host (Same Attack, Successfully Blocked)
 
| Hostname | IP | OS | User | Browser | Outcome |
|---|---|---|---|---|---|
| **BTUN-L** | 192.168.3.130 | Windows | BillyTun | Chrome and Edge| 46 attempts blocked by Symantec EP |
 
### Hosts in DNS Beaconing Activity
 
The following 14 hosts showed beaconing behavior to `splunk.froth.ly` during the attack window. Investigation did not connect this DNS pattern to the CoinMiner attack. Hosts are documented for completeness:
 
- ip-172-16-0-109.ec2.internal
- mars.i-08e52f8b5a034012d
- matar
- BTUN-L
- PCERF-L
- JWORTOS-L
- gacrux.i-0920036c8ca91e501
- FYODOR-L
- BSTOLL-L
- ABUNGST-L
- MKRAEUS-L
- gacrux.i-06fea586f3d3c8ce8
- gacrux.i-09cbc261e84259b54
- gacrux.i-0cc93bade2b3cba63
---
 
## Behavioral Indicators
 
### CPU Patterns
 
- Browser process (Chrome) sustaining 100% CPU during active browsing of compromised forum
- Sustained 26-minute mining session (131 events at 99-100% CPU)
- Total CPU averaged 99.4% throughout the attack day
### Network Patterns
 
- DNS queries to coinhive.com clustered at session establishment (4 queries within 1 minute)
- No subsequent DNS activity to coinhive.com (consistent with WebSocket persistent connection)
- HTTP traffic to the compromised forum during the same window
### Timing Indicators
 
| Time | Activity |
|---|---|
| 09:07:23 | First HTTP request to compromised site |
| 09:37:40 | First Symantec block on protected host |
| 09:37:50 | Browser CPU first hits 100% on affected host |
| 09:38:19 | First C2 DNS resolution on affected host |
| 09:37:50 - 10:04:11 | Sustained mining session (~26 minutes) |
| 10:59:19 | Final isolated mining event |

---

## Threat Intelligence - Current State (2026)

This investigation analyzes a 2018 attack. CoinHive and JSCoinminer are no longer current threats. This section documents what changed and what still applies to SOC work today.

### CoinHive Status

CoinHive shut down March 8, 2019 after Monero's hash rate dropped 50% post-hard fork and XMR value dropped 85%. The coinhive.com domain is no longer operational for mining ([Krebs on Security](https://krebsonsecurity.com/2019/02/crytpo-mining-service-coinhive-to-call-it-quits/)). 

DNS queries to coinhive.com today indicate dormant infections or legacy detection rules, not active threats. Detection rules built solely around coinhive.com will miss current cryptomining activity.

### Current Cryptomining Threat Landscape

Cryptomining attacks shifted to other delivery methods after the shutdown of CoinHive.

XMRig has become the dominant cryptominer. It is open-source Monero mining software that can be used legitimately with consent, but is often deployed by attackers on compromised hosts via exploits, fake software updates, and bundled installers. CISA published a Malware Analysis Report (MAR-10387061-1.v1) on XMRig in 2022 after Iranian government-sponsored APT actors used it against a Federal Civilian Executive Branch network to harvest credentials ([CISA Advisory AA22-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a)).

Cloud infrastructure is a current target. Attackers target cloud environments because compute resources scale and detection is harder than on endpoints. Microsoft Threat Intelligence documented attacks exploiting OpenMetadata vulnerabilities (CVE-2024-28255, CVE-2024-28847, CVE-2024-28253, CVE-2024-28848, CVE-2024-28254) to compromise Kubernetes workloads for cryptomining in April 2024 ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/04/17/attackers-exploiting-new-critical-openmetadata-vulnerabilities-on-kubernetes-clusters/)). 

Initial access often comes from known vulnerabilities. According to the CISA advisory, attackers exploited Log4Shell (CVE-2021-44228) in an unpatched VMware Horizon server as the entry point before deploying XMRig.

### Why This Investigation Still Applies

The specific IOCs are outdated but the TTPs are not:

- Drive-by compromise via trusted third-party websites is still a top initial access vector
- JavaScript-based payloads still execute in browsers
- Resource hijacking is still the impact regardless of miner family
- Detection coverage gaps like BSTOLL-L's (no working endpoint protection) remain common
- CPU monitoring still works as a detection signal for XMRig and other CPU-based miners

---
 
## Detection Recommendations

The following detection rules would have surfaced this attack faster.

### Rule 1 - CoinHive DNS Lookup

```spl
sourcetype="stream:dns" query IN ("coinhive.com", "*.coinhive.com")
| stats count by host, query
```

**What it detects:** DNS queries to known CoinHive cryptocurrency mining infrastructure. Maps to T1071.001 (Application Layer Protocol: Web Protocols).

**False positive risk:** Low. CoinHive shut down in March 2019 and the domain is widely flagged as malicious by threat intel feeds. 

**Suggested controls:**
- Allowlist known security tool hosts (EDR, sandbox, threat intel platforms)
- Tag alerts by host role (workstation vs security infrastructure) for prioritization
- Expand the rule to include current cryptomining pool patterns (XMRig, Monero pools, web mining services that emerged after CoinHive sunsetted)

---

### Rule 2 - Chrome Sustained High CPU

```spl
sourcetype="PerfmonMk:Process" instance="*chrome*" %_Processor_Time>=90
| stats count by host, instance
| where count > 100
```

**What it detects:** Browser processes with sustained high CPU usage consistent with cryptocurrency mining. Maps to T1496 (Resource Hijacking).

**False positive risk:** High. Sustained 90%+ Chrome CPU is common in legitimate activity such as video calls (Zoom, Teams, Webex), video editing in browser-based tools, Adobe Lightroom exports, Chrome with many active tabs, streaming services, and heavy web applications (Figma, Linear, Notion).

**Suggested controls:**
- Process allowlist: exempt known high-CPU processes during business hours
- Multi-signal requirement: require CPU spike AND a corroborating indicator within 10 minutes (DNS query to mining infrastructure, EDR signature, outbound WebSocket to a non-business domain)
- Baseline comparison: compute the user's normal Chrome CPU pattern over a 14-day window and alert only when current usage exceeds baseline plus N standard deviations
- Time-of-day weighting: sustained 100% CPU at 3am on a workstation is more suspicious than the same usage at 2pm on a developer's machine
- Expand the rule to cover Edge and Firefox since drive-by mining attacks target whichever browser the user has open

---

### Rule 3 - JSCoinminer Symantec Baseline

```spl
index=botsv3 sourcetype="symantec:ep:security:file"
("JSCoinminer" OR SID=30356 OR SID=30358)
| stats count by host, _time
| sort _time
```

**What it detects:** Symantec Endpoint Protection detections of JSCoinminer attempts. Maps to T1189 (Drive-by Compromise).

**False positive risk:** Low. Symantec JSCoinminer signatures fire on known malicious patterns and are tuned by the vendor.

**Suggested controls:**
- Tag detections from sandbox or security infrastructure hosts separately
- Correlate JSCoinminer detections on one host with CPU anomalies on adjacent hosts within the same subnet (the 10-second gap between BTUN-L's first Symantec block and BSTOLL-L's mining onset is the lesson here)
- When Symantec blocks JSCoinminer on any host, elevate monitoring on hosts that visited the same compromised URL within the past hour

---

### Multi-Indicator Detection

Browser process with sustained high CPU + DNS query to known mining infrastructure within 10 minutes = high-confidence cryptomining alert. Combining Rule 1 and Rule 2 reduces false positives compared to either rule alone.

---
 
## MITRE ATT&CK Mapping
 
| Technique | ID | Indicator Type |
|---|---|---|
| Drive-by Compromise | T1189 | Compromised legitimate site delivering payload site-wide |
| JavaScript Execution | T1059.007 | Malicious JS executing in browser |
| Application Layer Protocol: Web Protocols | T1071.001 | DNS resolution to known C2 infrastructure (coinhive.com) |
| Resource Hijacking | T1496 | Sustained CPU consumption for cryptocurrency mining |
 
---
 
*All IOCs were identified through direct evidence in the BOTSv3 dataset. Source queries are documented in the main README.md.*
