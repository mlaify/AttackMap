# AttackMap Vulnerability Disclosure Policy

## Introduction
AttackMap welcomes feedback from security researchers and the general public to help improve our security. If you believe you have discovered a vulnerability, privacy issue, exposed data, or other security issues in any of our assets, we want to hear from you. This policy outlines steps for reporting vulnerabilities to us, what we expect, what you can expect from us.

## Systems in Scope
This policy applies to any digital assets owned, operated, or maintained by AttackMap.

## Out of Scope
Assets or other equipment not owned by parties participating in this policy.

Vulnerabilities discovered or suspected in out-of-scope systems should be reported to the appropriate vendor or applicable authority.

## Our Commitments
When working with us, according to this policy, you can expect us to:
- Respond to your report promptly, and work with you to understand and validate your report;
- Strive to keep you informed about the progress of a vulnerability as it is processed;
- Work to remediate discovered vulnerabilities in a timely manner, within our operational constraints; and
- Extend Safe Harbor for your vulnerability research that is related to this policy.

## Our Expectations
In participating in our vulnerability disclosure program in good faith, we ask that you:
- Play by the rules, including following this policy and any other relevant agreements. If there is any inconsistency between this policy and any other applicable terms, the terms of this policy will prevail;
- Report any vulnerability you've discovered promptly;
- Avoid violating the privacy of others, disrupting our systems, destroying data, and/or harming user experience;
- Use only the Official Channel to discuss vulnerability information with us;
- Provide us a reasonable amount of time (at least 90 days from the initial report) to resolve the issue before you disclose it publicly;
- Perform testing only on in-scope systems, and respect systems and activities which are out-of-scope;
- If a vulnerability provides unintended access to data: Limit the amount of data you access to the minimum required for effectively demonstrating a Proof of Concept; and cease testing and submit a report immediately if you encounter any user data during testing, such as Personally Identifiable Information (PII), Personal Healthcare Information (PHI), credit card data, or proprietary information;
- You should only interact with test accounts you own or with explicit permission from the account holder; and
- Do not engage in extortion.

## Choosing the Right Channel
Use a public GitHub issue for ordinary bugs, crashes, installation problems, false positives, false negatives, incorrect findings, severity disagreements, feature requests, and documentation corrections. A finding in software analyzed by AttackMap is not a vulnerability in AttackMap.

Use private vulnerability reporting only for a credible vulnerability in this project itself. Automated scanner output without validation and a demonstrated project-specific impact is not sufficient by itself.

This is a coordinated vulnerability disclosure program, not a bug bounty. We do not offer or promise payment, rewards, or swag for reports.

## Official Channel
Report vulnerabilities through this repository's **Security** tab using **Report a vulnerability**. Do not put vulnerability details in a public issue, pull request, discussion, or comment.

## What to include in a report

GitHub's private reporting form has fixed fields, so cover these points in it:

- **Affected repository, component, and version:** the release, build, or commit if known.
- **Summary:** the security boundary that breaks.
- **Realistic impact:** what an attacker can read, change, execute, impersonate, or make
  unavailable, and who is affected.
- **Attacker prerequisites:** network position, authentication or role, local or physical
  access, user interaction, and configuration assumptions.
- **Reproduction or proof of concept:** minimal, safe steps that let the maintainer validate the
  issue, without data or credentials belonging to others.
- **Sanitized evidence:** logs, screenshots, traces, or code excerpts with secrets, personal
  data, proprietary source, and third-party data removed.
- **Suggested remediation,** if you have one.
- **Disclosure and credit preference:** timing constraints and the name or handle to credit, or
  a request for anonymity.

Before you submit, confirm that you tested only systems, devices, accounts, and data you own or
had explicit permission to test, and that the report concerns this project itself rather than an
ordinary bug, an incorrect result, or a third-party product. Automated scanner output without
validation and a demonstrated impact is not sufficient by itself.

## Safe Harbor
When conducting vulnerability research, according to this policy, we consider this research conducted under this policy to be:
- Authorized concerning any applicable anti-hacking laws, and we will not initiate or support legal action against you for accidental, good-faith violations of this policy;
- Authorized concerning any relevant anti-circumvention laws, and we will not bring a claim against you for circumvention of technology controls;
- Exempt from restrictions in our Terms of Service (TOS) and/or Acceptable Usage Policy (AUP) that would interfere with conducting security research, and we waive those restrictions on a limited basis; and
- Lawful, helpful to the overall security of the Internet, and conducted in good faith.

You are expected, as always, to comply with all applicable laws. If legal action is initiated by a third party against you and you have complied with this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please submit a report through the Official Channel before going any further.

Note that the Safe Harbor applies only to legal claims under the control of the organization participating in this policy, and that the policy does not bind independent third parties.
