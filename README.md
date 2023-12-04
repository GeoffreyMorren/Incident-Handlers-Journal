<h1 align="center">Incident Handler's Journal</h1>

**Date:**  
10/14/2023

**Entry: Journal entry #1**  
**Description**  
Unethical hackers infiltrated a U.S. health care clinic through phishing emails, encrypted vital files with ransomware, and demanded payment for a decryption key, causing a disruptive security incident.

**Tool(s) used**  
None.

**The 5 W's**  
**Who caused the incident?**  
The incident was caused by an organized group of unethical hackers who targeted the U.S. health care clinic.

**What happened?**  
The hackers gained access to the clinic's network through targeted phishing emails, installed malware on employee computers, and then deployed ransomware to encrypt critical files. As a result, the clinic's employees were unable to access their files, including medical records, and received a ransom note demanding payment for a decryption key.

**When did the incident occur?**  
The incident occurred on a Tuesday morning at approximately 9:00 a.m.

**Where did the incident happen?**  
The incident happened at a small U.S. health care clinic specializing in delivering primary-care services.

**Why did the incident happen?**  
The incident happened because the hackers gained access to the clinic's network through targeted phishing emails, indicating that they had a specific interest in targeting the health care industry. They deployed ransomware to encrypt critical files with the intention of extorting money from the clinic in exchange for the decryption key.

**Additional notes**  
To prevent similar incidents in the future, the health care clinic should consider:
1. Employee Training: Provide comprehensive cybersecurity training to staff to recognize and avoid phishing emails and suspicious attachments.
2. Email Filtering: Implement robust email filtering systems to detect and block phishing emails before they reach employees' inboxes.
3. Regular Updates and Patching: Keep software and systems up to date with the latest security patches to fix vulnerabilities that hackers often exploit.
4. Data Backup and Recovery: Regularly back up critical data and test the backups to ensure data recovery in case of a ransomware attack.
5. Multi-Factor Authentication (MFA): Enforce MFA for accessing sensitive systems and data to add an extra layer of security.
6. Network Segmentation: Isolate critical systems and sensitive data from the broader network, limiting the potential impact of a breach.
7. Incident Response Plan: Develop a well-documented incident response plan to guide actions in case of a security breach, including reporting to authorities and cybersecurity professionals.
8. Regular Security Audits: Conduct routine security assessments and audits to identify vulnerabilities and weaknesses in the network.
9. Vendor Security: Ensure third-party vendors and software used are also secure to avoid potential supply chain vulnerabilities.
10. Strong Password Policies: Implement strict password policies, encouraging the use of complex, unique passwords and regular password changes.
11. Cybersecurity Insurance: Consider obtaining cybersecurity insurance to mitigate the financial impact of a security incident.
12. Collaborate with Cybersecurity Experts: Regularly consult with cybersecurity experts to stay updated on evolving threats and security best practices.

**Date:**  
10/16/2023

**Entry: Journal entry #2**  
**Description**  
Investigate a suspicious file hash

**Tool(s) used**  
VirusTotal

**The 5 W's**  
**Who caused the incident?**  
The incident was caused by an external actor who sent the malicious email with the password-protected spreadsheet attachment to the employee.

**What happened?**  
The employee received an email with an attachment, and the attachment was password-protected. The employee followed the instructions in the email and entered the provided password to open the file. Upon opening the file, a malicious payload was executed on the employee's computer. This payload contained the malware Flagpro, commonly used by BlackTech, designed to compromise the computer's security or steal information.

**When did the incident occur?**  
Between 1:11 p.m. and 1:20 p.m.

**Where did the incident happen?**  
The incident occurred on the employee's computer when they opened the malicious attachment.

**Why did the incident happen?**  
The incident likely happened as part of a cyberattack aimed at compromising the employee's computer and possibly gaining unauthorized access to the financial services company's data or systems. The attacker used a spear-phishing email that tricked the employee into opening the malicious attachment.

**Additional notes**  
- Domain names: org.misecure.com is reported as a malicious contacted domain under the Relations tab in the VirusTotal report.
- IP address: 207.148.109.242 is listed as one of many IP addresses under the Relations tab in the VirusTotal report. This IP address is also associated with the org.misecure.com domain as listed in the DNS Resolutions section under the Behavior tab from the Zenbox sandbox report.
- Hash value: 287d612e29b71c90aa54947313810a25 is an MD5 hash listed under the Details tab in the VirusTotal report.
- Network/host artifacts: Network-related artifacts that have been observed in this malware are HTTP requests made to the org.misecure.com domain. This is listed in the Network Communications section under the Behavior tab from the Venus Eye Sandbox and Rising MOVES sandbox reports.
- Tools: Input capture is listed in the Collection section under the Behavior tab from the Zenbox sandbox report. Malicious actors use input capture to steal user input such as passwords, credit card numbers, and other sensitive information.
- TTPs: Command and control is listed as a tactic under the Behavior tab from the Zenbox sandbox report. Malicious actors use command and control to establish communication channels between an infected system and their own system.

**Date:**  
10/16/2023

**Entry: Journal entry #3**  
**Description**  
Use a playbook to respond to a phishing incident

**Tool(s) used**  
None.

**The 5 W's**  
**Who caused the incident?**  
The incident was likely caused by an external threat actor who sent the phishing email.

**What happened?**  
An employee received a phishing email with an attachment. The email impersonated an applicant expressing interest in a job role. The attachment, named "bfsvc.exe," was provided along with a password ("paradise10789") to open the attachment. The malicious aspect of this incident is the attachment itself, which is a known malicious file with the SHA256 hash "54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b."

**When did the incident occur?**  
The email was sent on Wednesday, July 20, 2022, at 09:30:14 AM, as indicated in the email timestamp.

**Where did the incident happen?**  
The incident happened on the recipient's computer, which is located within the financial services company. The email was sent from an IP address (114.114.114.114), but the recipient's IP address (176.157.125.93) is also provided.

**Why did the incident happen?**  
The primary goal of this incident was to deliver a malicious file (bfsvc.exe) to the recipient's computer. The attacker used social engineering tactics to create a seemingly legitimate email, impersonating a job applicant. By claiming the attachment is a resume and providing a password for privacy, the attacker attempted to trick the recipient into opening the malicious file. The attacker's motive might be to compromise the recipient's computer, gain unauthorized access, or deliver malware.

**Additional notes**  
The alert detected that an employee downloaded and opened a malicious file from a phishing email. There is an inconsistency between the sender’s email address “76tguy6hh6tgftrt7tg.su’” the name used in the email body “Clyde West,” and the sender’s name, “Def Communications.” The email body and subject line contained grammatical errors. The email’s body also contained a password-protected attachment, “bfsvc.exe,” which was downloaded and opened on the affected machine. Having previously investigated the file hash, it is confirmed to be a known malicious file. Furthermore, the alert severity is reported as medium. With these findings, I chose to escalate this ticket to a level-two SOC analyst to take further action.

**Date:**  
10/17/2023

**Entry: Journal Entry #4**  
**Description**  
Perform a query with Splunk

**Tool(s) used**  
Splunk Cloud

**The 5 W's**  
**Who caused the incident?**  
An unknown threat actor is responsible for the incident.

**What happened?**  
There was a substantial increase in login attempts targeting the mail server.

**When did the incident occur?**  
The incident occurred from the 28th of February until the 6th of March 2023.

**Where did the incident happen?**  
The incident occurred on the mail server, which is a critical component of the Buttercup Games e-commerce infrastructure.

**Why did the incident happen?**  
The incident likely happened with the intent to potentially gain unauthorized access to the mail server, raising concerns about security vulnerabilities and unauthorized access to sensitive data.

**Additional notes**  
With over 300 failed login attempts logged during the specified time frame, it's evident that this incident involved a significant number of unauthorized access attempts. The high volume of failed login events raises concerns about the security of the mail server and the persistence of the unknown threat actor attempting to gain access. It's essential to investigate further and take appropriate security measures to prevent potential breaches and mitigate any existing vulnerabilities in the system.

**Date:**  
10/17/2023

**Entry: Journal Entry #5**  
**Description**  
Perform a query with Chronicle

**Tool(s) used**  
Google Chronicle

**The 5 W's**  
**Who caused the incident?**  
The phishing incident was caused by an external threat actor or group who set up the domain "signin.office365x24.com" and used it for malicious purposes.

**What happened?**  
Employees at the financial services company received phishing emails containing links to the domain "signin.office365x24.com," and some of them accessed the link, potentially compromising their data.

**When did the incident occur?**  
The incident occurred between January 31 and July 09, 2023, spanning several months.

**Where did the incident happen?**  
The incident took place within the organization, with multiple employees being targeted and interacting with the malicious domain.

**Why did the incident happen?**  
The incident happened with the intent to deceive employees into clicking on the phishing links, leading to the compromise of their credentials and data, potentially for financial gain or unauthorized access to company resources. The domain "signin.office365x24.com" was categorized as a drop site for logs or stolen credentials, indicating an intent to harvest sensitive information.

**Additional notes**  
Include any additional thoughts, questions, or findings.
