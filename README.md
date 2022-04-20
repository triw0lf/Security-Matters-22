# Security Matters 2022 Resource List

## Overview

Collection of resources for defending against current threat lanscape trends and improving security knowledge

Table of Contents
=================

* [Security Matters 2022 Resource List](#security-matters-2022-resource-list)
   * [Overview](#overview)
   * [Common Attack Tools](#common-attack-tools)
      * [Most Common Attack Tool List](#most-common-attack-tool-list)
      * [Defenses](#defenses)
   * [Supply Chain Attacks](#supply-chain-attacks)
      * [Well Known Supply Chain Attacks](#well-known-supply-chain-attacks)
      * [Defenses](#defenses-1)
   * [Vulnerability Exploitation](#vulnerability-exploitation)
      * [Known Vulnerabilities](#known-vulnerabilities)
      * [Defenses](#defenses-2)
   * [ECrime](#ecrime)
      * [ECrime Threat Actors](#ecrime-threat-actors)
      * [Defenses](#defenses-3)
   * [Ransomware](#ransomware)
      * [Defenses](#defenses-4)
   * [Threat Intelligence Reports](#threat-intelligence-reports)
   * [Networking Resources](#networking-resources)
      * [Law Enforcement](#law-enforcement)
      * [Information Sharing Organizations](#information-sharing-organizations)
      * [Community Outreach](#community-outreach)
      * [Conferences](#conferences)


## Common Attack Tools

### Most Common Attack Tool List

| Resource | Notes |
| ------------- | ------------- |
| https://github.com/gentilkiwi/mimikatz  | Mimikatz  |
| https://github.com/rapid7/metasploit-framework  | Metasploit  |
| https://github.com/PowerShellMafia/PowerSploit | PowerSploit |
| https://www.cobaltstrike.com/ | Cobalt Strike |
| https://github.com/BloodHoundAD/BloodHound | Bloodhound |

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| https://isc.sans.edu/forums/diary/Mitigations+against+Mimikatz+Style+Attacks/24612/ | Mitigations against Mimikatz Style Attacks |
| https://www.securitynewspaper.com/2021/09/23/8-techniques-to-protect-your-windows-network-domains-against-mimikatz-credential-stealing-tool/] | 8 Techniques to Prevent Mimikatz |
| https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5 | Preventing Mimikatz Attacks |
| https://sansorg.egnyte.com/dl/XMHRwR5lRO | SANS: Mimikatz Overview, Detections and Defenses |
| https://www.pwndefend.com/2021/03/19/owa-pwnage/ | OWA Stuffing with Metasploit Detections and Preventions | 
| https://adsecurity.org/?p=2921 | PowerShell Security: PowerShell Attack Tools, Mitigation, & Detection (PowerSploit) | 
| https://adsecurity.org/?p=2604 | Detecting Offensive PowerShell Attack Tools (PowerSploit) |
| https://robwillis.info/2021/02/defending-against-powershell-attacks/ | Defending Against Powershell Attacks (PowerSploit) |
| https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/ | Cobalt Strike, a Defender’s Guide | 
| https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence | Awesome Cobalt Strike Defense | 
| https://www.crowdstrike.com/blog/how-to-block-bloodhound-attacks/ | How to Sniff Out (and Block) BloodHound Attacks | 
| https://www.microsoft.com/security/blog/2020/08/27/stopping-active-directory-attacks-and-other-post-exploitation-behavior-with-amsi-and-machine-learning/ | Stopping Active Directory attacks and other post-exploitation behavior with AMSI and machine learning |
| https://posts.specterops.io/bloodhound-versus-ransomware-a-defenders-guide-28147dedb73b | BloodHound versus Ransomware: A Defender’s Guide |
| https://0x1.gitlab.io/pentesting/Active-Directory-Kill-Chain-Attack-and-Defense/ | Active Directory Kill Chain Attack and Defense | 

## Supply Chain Attacks

### Well Known Supply Chain Attacks

| Resource | Notes |
| ------------- | ------------- |
| https://www.okta.com/blog/2022/03/oktas-investigation-of-the-january-2022-compromise/ | Okta + Sykes/Sitel Breach |
| https://www.mandiant.com/resources/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor | SolarWinds Attack |
| https://www.zdnet.com/article/updated-kaseya-ransomware-attack-faq-what-we-know-now/ | Kaseya Breach |
| https://www.zdnet.com/article/log4j-flaw-hunt-shows-how-complicated-the-software-supply-chain-really-is/ | Log4j Attack | 

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| https://media.defense.gov/2022/Feb/24/2002944158/-1/-1/1/DOD-EO-14017-REPORT-SECURING-DEFENSE-CRITICAL-SUPPLY-CHAINS.PDF | Securing Defense-Critical Supply Chains: An action plan developed in response to President Biden's Executive Order 14017|
| https://www.cisa.gov/supply-chain-compromise | CISA: Supply Chain Compromises |
| https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_508_1.pdf | Defending against Software Supply Chain Attacks - CISA |
| https://docs.microsoft.com/en-us/microsoft-365/security/intelligence/supply-chain-malware?view=o365-worldwide | Supply chain malware |

## Vulnerability Exploitation

### Known Vulnerabilities

| Resource | Notes |
| ------------- | ------------- |
| https://www.cisa.gov/uscert/ncas/alerts/aa21-209a | CISA: Top Routinely Exploited Vulnerabilities |
| https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CISA: Known Exploited Vulnerabilities |
| https://www.vpls.com/blog/top-exploited-cybersecurity-vulnerabilities-of-2020-2021/ | Top Exploited Cybersecurity Vulnerabilities of 2020 and 2021 (So Far) |
| https://www.tenable.com/blog/behind-the-scenes-how-we-picked-2021s-top-vulnerabilities-and-what-we-left-out | Behind the Scenes: How We Picked 2021’s Top Vulnerabilities – and What We Left Out |

Palo Alto Networks Most Exploited CVEs by Ransomware Ganges:
1.	CVE-2017-0199
2.	CVE-2017-11882
3.	CVE-2018-13379
4.	CVE-2019-0604
5.	CVE-2019-0708
6.	CVE-2019-11510
7.	CVE-2019-11634
8.	CVE-2019-5591
9.	CVE-2019-7481
10.	CVE-202-5902
11.	CVE-2020-12271
12.	CVE-2020-12812
13.	CVE-2020-1472
14.	CVE-2020-36198
15.	CVE-2020-5135
16.	CVE-2020-8195
17.	CVE-2020-8196
18.	CVE-2020-8234
19.	CVE-2020-8260
20.	CVE-2021-20016
21.	CVE-2021-20655
22.	CVE-2021-2198
23.	CVE-2021-22893
24.	CVE-2021-22941
25.	CVE-2021-22986
26.	CVE-2021-26084
27.	CVE-2021-26855
28.	CVE-2021-2701
29.	CVE-2021-27102
30.	CVE-2021-27103
31.	CVE-2021-27104
32.	CVE-2021-28799
33.	CVE-2021-31166
34.	CVE-2021-31207
35.	CVE-2021-34473
36.	CVE-2021-34523
37.	CVE-2021-36942
38.	CVE-2021-38647
39.	CVE-2021-40444
40.	CVE-2021-40539
41.	CVE-2021-45046

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/tvm-zero-day-vulnerabilities?view=o365-worldwide | Mitigate zero-day vulnerabilities - threat and vulnerability management |
| https://www.cisa.gov/known-exploited-vulnerabilities | Reducing the signficant risk of known exploited vulnerabilities |
| https://csrc.nist.gov/publications/detail/sp/800-40/version-20/archive/2005-11-16 | Creating a Patch and Vulnerability Management Program | 
| https://www.cisa.gov/uscert/sites/default/files/recommended_practices/NCCIC_ICS-CERT_Defense_in_Depth_2016_S508C.pdf | Recommended Practice: Improving Industrial Control System Cybersecurity with Defense-in-Depth Strategies | 

## ECrime

### ECrime Threat Actors

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

## Ransomware

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

## Threat Intelligence Reports

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

## Networking Resources

### Law Enforcement

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

### Information Sharing Organizations

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

### Community Outreach

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

### Conferences 

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 


###End
