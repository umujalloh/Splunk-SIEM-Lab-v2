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
| **BTUN-L** | 192.168.3.130 | Windows | BillyTun | Chrome | 46 attempts blocked by Symantec EP |
 
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
 
## Detection Recommendations
 
Based on this investigation, the following detection rules would have surfaced this attack faster:
 
### DNS-Based Detection
 
```spl
sourcetype="stream:dns" query IN ("coinhive.com", "*.coinhive.com")
| stats count by host, query
```
 
### CPU-Based Detection
 
```spl
sourcetype="PerfmonMk:Process" instance="*chrome*" %_Processor_Time>=90
| stats count by host, instance
| where count > 100
```
 
### Multi-Indicator Detection
 
Browser process with sustained high CPU + DNS query to known mining infrastructure within 10 minutes = high-confidence cryptomining alert.
 
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
