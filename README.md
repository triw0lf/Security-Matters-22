# Security Matters 2022 Resource List

## Overview

Collection of resources for defending against current threat lanscape trends and improving security knowledge

Table of Contents
=================

* [Security Matters 2022 Resource List](#security-matters-2022-resource-list)
   * [Overview](#overview)
* [Table of Contents](#table-of-contents)
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
      * [Community Groups](#community-groups)
      * [Conferences](#conferences)
   * [Practice Opportunities](#practice-opportunities)


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
| https://www.mandiant.com/sites/default/files/2021-09/rpt-fin6-1.pdf | Follow the Money: Dissecting the Operations of FIN6 |
| https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/ | The DFIR Report: All that for a cryptominer? |
| https://www.cisa.gov/uscert/ncas/alerts/aa20-280a | Emotet Malware |
| https://www.proofpoint.com/us/blog/threat-insight/triple-threat-north-korea-aligned-ta406-scams-spies-and-steals | Triple Threat: North Korea-Aligned TA406 Scams, Spies, and Steals | 
| https://assets.sentinelone.com/sentinellabs/sentinellabs_EvilCorp | Sanctions Be Damned | From Dridex to Macaw, The Evolution of Evil Corp | 

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| https://www.trendmicro.com/en_us/research/21/f/secure_secrets_managing_authentication_credentials.html | Secure Secrets: Managing Authentication Credentials |
| https://www.beyondtrust.com/blog/entry/how-to-manage-and-secure-service-accounts-best-practices | How to Manage and Secure Service Accounts: Best Practices |
| https://cloud.google.com/blog/products/identity-security/account-authentication-and-password-management-best-practices | 13 best practices for user account, authentication, and password management, 2021 edition |
| https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory | Best Practices for Securing Active Directory |
| https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack | Securing Domain Controllers Against Attack |
| https://security.berkeley.edu/education-awareness/securing-remote-desktop-rdp-system-administrators | Securing Remote Desktop (RDP) for System Administrators |
| https://www.microsoft.com/security/blog/2020/04/16/security-guidance-remote-desktop-adoption/ | Security guidance for remote desktop adoption | 
| https://www.cisa.gov/uscert/ncas/alerts/aa20-073a | CISA: Enterprise VPN Security |
| https://media.defense.gov/2021/Sep/28/2002863184/-1/-1/0/CSI_SELECTING-HARDENING-REMOTE-ACCESS-VPNS-20210928.PDF | Selecting and Hardening Remote Access VPN Solutions|
| https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.security.doc/GUID-E9B71B85-FBA3-447C-8A60-DEE2AE1A405A.html | Securing the ESXi Hypervisor |
| https://downloads.cloudsecurityalliance.org/whitepapers/Best_Practices_for%20_Mitigating_Risks_Virtual_Environments_April2015_4-1-15_GLM5.pdf | Best Practices for Mitigating Risks in Virtualized Environments |
| https://cofense.com/real-phishing-examples-and-threats/ | Phishing Report Database |

## Ransomware

### Defenses 

| Resource | Notes |
| ------------- | ------------- |
| | |
| | | 

## Threat Intelligence Reports

| Resource | Notes |
| ------------- | ------------- |
| [Palo Alto Ransomware Report](repo/blob/master/main/Threat Intelligence Reports/2022-unit42-ransomware-threat-report-final.pdf) | |
| | | 

## Networking Resources

### Law Enforcement

| Resource | Notes |
| ------------- | ------------- |
| https://www.fbi.gov/contact-us/field-offices/louisville | FBI Field Office - Louisville |
| https://www.fbi.gov/contact-us/field-offices/indianapolis | FBI Field Office - Indianapolis | 
| https://www.fbi.gov/contact-us/field-offices/knoxville | FBI Field Office - Knoxville | 
| https://www.fbi.gov/contact-us/field-offices/memphis | FBI Field Office - Memphis | 
| https://www.fbi.gov/contact-us/field-offices/springfield | FBI Field Office - Springfield | 
| https://www.fbi.gov/contact-us/field-offices/stlouis | FBI Field Office - Saint Louis | 
| https://www.cisa.gov/uscert/resources/business# | CISA Cyber Security Advisors | 
| https://www.cisa.gov/critical-infrastructure-partnership-advisory-council | CISA Critical Infrastructure Partnership Advisory Council | 
| https://www.cisa.gov/critical-infrastructure-partnership-advisory-council | CISA Region 4 - Kentucky, Tennessee | 
| https://www.cisa.gov/region-7 | CISA Region 7 - Missouri | 
| https://www.cisa.gov/region-5 | CISA Region 5 - Illinois | 
| https://www.cisa.gov/partnership-engagement-branch | CISA Partnership and Engagement | 

### Information Sharing Organizations

| Resource | Notes |
| ------------- | ------------- |
| https://www.nationalisacs.org/ | National Council of Information Sharing and Analysis Centers (ISAC) |
| https://www.fsisac.com | Financial Services ISAC 
| https://www.dngisac.com/ | Downstream Natural Gas ISAC |
| https://www.eisac.com/ | Electricity ISAC | 
| https://healthcareready.org/ | Healthcare Ready |
| https://h-isac.org/ | Health ISAC |
| https://www.it-isac.org/ | Information Technology ISAC |
| https://www.cisecurity.org/ms-isac | Multistate ISAC |
| https://ongisac.org/ | Oil and Natural Gas ISAC |
| https://www.ren-isac.net/ | Research and Education Networks ISAC |
| https://www.rhisac.org/ | Retail and Hospitality ISAC |
| https://www.ntca.org/member-services/cybershare | Small Broadband ISAC |
| https://www.waterisac.org/ | Water ISAC |
| https://www.isao.org/information-sharing-groups/ | Information Sharing and Analysis Organizations (ISAO) |
| https://www.acscenter.org/ | Advanced Cyber Security Center |
| https://ciasisao.org/ |  Center for Infrastructure Assurance and Security  ISAO |
| https://www.cyberusa.us/ | CyberUSA |
| https://midwestcybercenter.org/ | Midwest Cyber Center |
| https://www.cyberthreatalliance.org/ | Cyber Threat Alliance |
| https://faithbased-isao.org/ | Faith Based ISAO |
| https://www.energysec.org/ | EnergySec |
| https://www.in.gov/cybersecurity/ | Indiana ISAC |
| https://www.k12six.org/ | K12 ISAO |
| https://ncuisao.org/ | National Credit Union ISAO |
| | |
| | |
| | |
| | |
| | |
| | |

### Community Groups

| Resource | Notes |
| ------------- | ------------- |
| https://www.meetup.com/STL-CYBER-Meetup/ | STL Cyber - security meetup in Saint Louis |
| https://www.meetup.com/OWASP-STL/ | OWASP Saint Louis |
| https://www.meetup.com/NashSec/ | NashSEC |
| https://www.meetup.com/OWASP-Nashville-Chapter/ | OWASP Nashville |
| https://www.meetup.com/DevSecHops-Louisville/ | DevSecHops Louisville |
| https://www.meetup.com/DevSecHops-Lexington/ | DevSecHops Lexington |
| https://seckc.org | SecKC - Kansas City | 

### Conferences 

| Resource | Notes |
| ------------- | ------------- |
| https://cybersecuritysummit.com/summit/nashville22/ | Cyber Seccurity Summit Nashville |
| https://bsidesnash.org/ | BSides Nashville |
| https://cybersecuritysummit.com/summit/stlouis22/ | Cyber Seccurity Summit Saint Louis | 
| https://bsidesstl.org/ | BSides Saint Louis |
| https://www.kychamber.com/events/education/security | Kentucky Chamber of Commerce Cybersecurity Conference |
| https://www.ky-cae.com/ | Kentucky Cybersecurity and Forensics Conference | 

## Practice Opportunities

| Resource | Notes |
| ------------- | ------------- |
| https://tryhackme.com/ | TryHackMe - specifically look at Cyber Defense path |
| https://www.hackthebox.com/ | HackTheBox |
| https://www.rangeforce.com/blog/free-cyber-security-training | RangeForce |
| https://www.blackhillsinfosec.com/services/cyber-range/ | Black Hills Information Security | 


### End
