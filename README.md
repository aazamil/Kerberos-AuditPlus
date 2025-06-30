# Kerberos-AuditPlus

A comprehensive PowerShell script to audit Kerberos hardening settings in Active Directory environments.

##  What It Audits

- PAC Validation
- Kerberos Armoring (FAST)
- AES Encryption usage
- RC4 usage and RC4-only accounts
- Delegation settings (Constrained, Unconstrained, Resource-Based)
- Smart Card enforcement for Domain Admins
- Duplicate SPNs
- Logon Auditing configuration
- TGT Lifetime
- SIDHistory usage on privileged accounts
- Kerberos Pre-Authentication settings
- Kerberoastable user accounts
- Time Skew between host and domain controllers
- NTLM usage policy

##  Requirements

- PowerShell 5.1+
- Active Directory PowerShell module
- Domain Controller (or admin workstation with RSAT)

##  Usage

Run the script on a Domain Controller:

```powershell
.\InvokeAuditPlus.ps1
