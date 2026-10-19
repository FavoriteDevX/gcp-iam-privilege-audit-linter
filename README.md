# 🛡️ GCP IAM Privilege Audit Linter

> A static security analysis tool tailored for Google Cloud Platform (GCP) IAM templates to track structural design flaws, eliminate unsafe primitive definitions (`roles/editor`), and prevent catastrophic bucket accessibility leaks.

<img width="1697" height="597" alt="image" src="https://github.com/user-attachments/assets/d3b52966-b8ef-4668-9a0b-05d0d151667a" />

## 🧯 Automated Security Checks
*   **Primitive Role Interception:** Flags and blocks traditional blanket roles, steering deployment states into granular pre-defined Google permissions maps.
*   **Public Access Blocks:** Sniffs bindings containing `allUsers` or `allAuthenticatedUsers` strings to prevent unintended public exposure of private corporate cloud buckets.

## Setup Syntax Execution
```bash
npm install
node linter_core.js
```
