# Exploitarium Corpus — Cross-Reference

> **Comprehensive cross-reference for all 23 vulnerability entries.**
> Indexed by: severity, type, language, target product, CWE, discovery method, and more.

---

## 1. By Entry ID

| ID | Title | Severity | Type | Product |
|----|-------|----------|------|---------|
| EX-001 | AnyDesk Printer Pipe COM Impersonation | High | LPE | AnyDesk 9.7.6 |
| EX-002 | VLC VP9 Resolution-Change Stale Allocation | Medium | Heap Overflow | VLC 3.0.23 |
| EX-003 | Docker cp Copy-Out Destination Escape | High | TOCTOU | Docker 29.6.0 |
| EX-004 | PHP 8.5.7 StreamBucket → SOAP RCE | **Critical** | Type Confusion RCE | PHP 8.5.7 |
| EX-005 | objdump DLX Backend Calc PoC | High | Parser ACE | Binutils 2.46.1 |
| EX-006 | c-ares TCP ares_getaddrinfo() UAF | **Critical** | UAF → Calc | c-ares main/v1.34.6 |
| EX-007 | 7-Zip RAR5 MotW/ADS Chain | High | Defender Bypass | 7-Zip 26.01 |
| EX-008 | Ghidra 12.1.2 Conditional ACE/RCE | High | Conditional RCE | Ghidra 12.1.2 |
| EX-009 | nghttp2 nghttpx HTTP/1.1 Upgrade Queue Poison | High | HTTP Smuggling | nghttp2 v1.69.0 |
| EX-010 | **libssh2 CVE-2026-55200** Packet Length Wrap | **Critical** | Integer Overflow | libssh2 ≤1.11.1 |
| EX-011 | RustDesk Session Permission Issues (2 findings) | High | Auth Bypass | RustDesk ff226f6d8 |
| EX-012 | FFmpeg RASC DLTA Heap OOB-W → Calc | **Critical** | OOB-W → Calc | FFmpeg master |
| EX-013 | MyBB 1.8.40 Limited ACP → Full Admin | High | Priv Esc | MyBB 1.8.40 |
| EX-014 | Gitea act_runner Container Options Bypass | High | Container Escape | Gitea act_runner |
| EX-015 | Floci 1.5.27 VTL RCE + IAM Bypass | **Critical** | RCE + Auth Bypass | Floci 1.5.27 |
| EX-016 | System Informer phsvc Trusted-Host LPE | High | LPE | System Informer 4.0 |
| EX-017 | ImageMagick GS Delegate Search Path Hijack | High | Search Path Hijack | ImageMagick 7.1.2 |
| EX-018 | Lunar Client Modrinth Explore 10-Stage Chain | **Critical** | RCE Chain | Lunar Client |
| EX-019 | libssh2 Publickey List Calc (Win32/Win64) | **Critical** | Int Overflow / UAF | libssh2 master |
| EX-020 | OpenVPN Connect Echo Script ACE | High | Server-Pushed ACE | OpenVPN Connect 3.8.0 |
| EX-021 | Firefox Smart Window Private URL Exfil | High | Info Leak | Firefox 152.0.2 |
| EX-022 | Nmap IPv6 Extension Length Wrap | Medium | Parser Bug | Nmap latest |
| EX-023 | Flowise MCP Env Case Bypass | High | Case-Sensitive Bypass | Flowise 3.1.2 |

---

## 2. By Severity

### Critical (7)
| ID | Title | CWE | Key Primitive |
|----|-------|-----|---------------|
| EX-004 | PHP 8.5.7 StreamBucket → SOAP RCE | CWE-843 | Type confusion → function pointer overwrite |
| EX-006 | c-ares TCP ares_getaddrinfo() UAF | CWE-416 | Skip-list destructor callback |
| EX-010 | libssh2 CVE-2026-55200 | CWE-190 | 19-byte allocation → overflow |
| EX-012 | FFmpeg RASC DLTA Heap OOB-W → Calc | CWE-787 | Row boundary overflow → callback redirection |
| EX-015 | Floci VTL RCE + IAM Bypass | CWE-94/862 | Velocity template injection |
| EX-018 | Lunar Client Modrinth Chain | CWE-79 | 10-stage Electron IPC chain |
| EX-019 | libssh2 Publickey Calc (Win32/Win64) | CWE-190/416 | Integer overflow + UAF |

### High (14)
| ID | Title | CWE | Key Primitive |
|----|-------|-----|---------------|
| EX-001 | AnyDesk COM Impersonation LPE | CWE-269 | COM callback via named pipe |
| EX-003 | Docker cp TOCTOU Escape | CWE-367 | Raced symlink in tar extraction |
| EX-005 | objdump DLX Calc PoC | CWE-787 | OOB-W in obscure backend |
| EX-007 | 7-Zip RAR5 MotW/ADS Chain | CWE-178 | NTFS stream name normalization |
| EX-008 | Ghidra Conditional ACE/RCE | CWE-78 | Process-launch + debugger agent |
| EX-009 | nghttp2 HTTP Upgrade Queue Poison | CWE-444 | Request smuggling |
| EX-011 | RustDesk Permission Issues | CWE-862 | Session downgrade + scope bypass |
| EX-013 | MyBB ACP → Full Admin | CWE-862 | Unconditional verify_usergroup() |
| EX-014 | Gitea act_runner Container Escape | CWE-284 | Host namespace option preservation |
| EX-016 | System Informer phsvc LPE | CWE-346 | Image trust vs. code identity |
| EX-017 | ImageMagick GS Delegate Hijack | CWE-426 | Bare executable search path |
| EX-020 | OpenVPN Connect Echo ACE | CWE-862 | Server-pushed script bypass |
| EX-021 | Firefox Smart Window Info Leak | CWE-200 | Multi-flag security state gap |
| EX-023 | Flowise MCP Env Case Bypass | CWE-178 | Case-sensitive check on Windows |

### Medium (2)
| ID | Title | CWE | Key Primitive |
|----|-------|-----|---------------|
| EX-002 | VLC VP9 Resolution-Change Crash | CWE-122 | Stale allocation overflow |
| EX-022 | Nmap IPv6 Extension Length Wrap | CWE-190 | Unsigned wraparound |

---

## 3. By Vulnerability Type

| Type | Count | Entries |
|------|-------|---------|
| **RCE / ACE** | 7 | EX-004, EX-005, EX-008, EX-015, EX-018, EX-020, EX-023 |
| **UAF → Calc** | 2 | EX-006, EX-019 (Win64) |
| **OOB-W → Calc/RCE** | 2 | EX-010, EX-012 |
| **Local Privilege Escalation** | 2 | EX-001, EX-016 |
| **Privilege Escalation (Web)** | 1 | EX-013 |
| **Auth Bypass** | 1 | EX-011 |
| **Container Escape** | 1 | EX-014 |
| **HTTP Request Smuggling** | 1 | EX-009 |
| **Information Disclosure** | 1 | EX-021 |
| **Parser Bug / DoS** | 2 | EX-002, EX-022 |
| **Defender Bypass (MotW)** | 1 | EX-007 |
| **TOCTOU / Race** | 1 | EX-003 |
| **Search Path Hijack** | 1 | EX-017 |
| **Total** | **23** | |

---

## 4. By Language

| Language | Count | Entries |
|----------|-------|---------|
| **C / C++** | 8 | EX-002, EX-005, EX-006, EX-010, EX-012, EX-016, EX-019, EX-022 |
| **PHP** | 2 | EX-004, EX-013 |
| **JavaScript / TypeScript / Electron** | 3 | EX-018, EX-021, EX-023 |
| **Go** | 2 | EX-003, EX-014 |
| **Java** | 2 | EX-008, EX-015 |
| **Rust** | 1 | EX-011 |
| **C++ (multi-stack)** | 2 | EX-001, EX-020 |
| **C#** | 1 | EX-017 |

---

## 5. By Target Product

| Product | Entry | Type |
|---------|-------|------|
| AnyDesk | EX-001 | LPE |
| VLC / FFmpeg | EX-002 | DoS / Stale Allocation |
| Docker | EX-003 | TOCTOU Escape |
| PHP | EX-004 | RCE |
| GNU Binutils (objdump) | EX-005 | Parser ACE |
| c-ares | EX-006 | UAF |
| 7-Zip | EX-007 | Defender Bypass |
| Ghidra | EX-008 | Conditional RCE |
| nghttp2 (nghttpx) | EX-009 | HTTP Smuggling |
| libssh2 | EX-010 | Integer Overflow RCE |
| RustDesk | EX-011 | Auth Bypass |
| FFmpeg | EX-012 | OOB-W → Calc |
| MyBB | EX-013 | Priv Esc |
| Gitea act_runner | EX-014 | Container Escape |
| Floci | EX-015 | RCE + IAM Bypass |
| System Informer | EX-016 | LPE |
| ImageMagick | EX-017 | Search Path Hijack |
| Lunar Client | EX-018 | RCE Chain |
| libssh2 | EX-019 | Int Overflow / UAF |
| OpenVPN Connect | EX-020 | ACE |
| Firefox | EX-021 | Info Leak |
| Nmap | EX-022 | Parser Bug |
| Flowise | EX-023 | Case Bypass ACE |

---

## 6. By CWE Top 10 Coverage

| CWE | Name | Entries |
|-----|------|---------|
| CWE-78 | OS Command Injection | EX-008 |
| CWE-79 | Cross-Site Scripting | EX-018 |
| CWE-94 | Code Injection | EX-015 |
| CWE-122 | Heap-based Buffer Overflow | EX-002 |
| CWE-178 | Case Sensitivity Mismatch | EX-007, EX-023 |
| CWE-190 | Integer Overflow | EX-010, EX-019, EX-022 |
| CWE-200 | Information Exposure | EX-021 |
| CWE-269 | Improper Privilege Management | EX-001 |
| CWE-284 | Improper Access Control | EX-014 |
| CWE-346 | Origin Validation Error | EX-016 |
| CWE-367 | TOCTOU Race Condition | EX-003 |
| CWE-416 | Use After Free | EX-006, EX-019 |
| CWE-426 | Untrusted Search Path | EX-017 |
| CWE-444 | Inconsistent HTTP Interpretation | EX-009 |
| CWE-787 | Out-of-bounds Write | EX-005, EX-012 |
| CWE-843 | Type Confusion | EX-004 |
| CWE-862 | Missing Authorization | EX-011, EX-013, EX-015, EX-020 |

---

## 7. By Discovery Method

| Method | Count | Entries |
|--------|-------|---------|
| **Manual code / source review** | 23 of 23 | Every entry is fundamentally source-driven (incl. the targeted audits in EX-004 and EX-008) |
| **Fuzzing** (structure-aware / coverage-guided / ASAN) | 5 | EX-002, EX-005, EX-006, EX-012, EX-022 |
| **Static analysis** (incl. CodeQL / Semgrep) | 4 | EX-005, EX-006, EX-010, EX-019 |
| **Process / IPC monitoring** | 3 | EX-001, EX-016, EX-017 |
| **Platform / OS-specific knowledge** | 3 | EX-007, EX-017, EX-023 |
| **Protocol analysis** | 2 | EX-011, EX-020 |
| **ASAN / sanitizer builds** | 2 | EX-002, EX-012 |

---

## 8. Exploit Primitive Index

| Primitive | Count | Entries |
|-----------|-------|---------|
| Integer overflow → undersized allocation → overflow | 3 | EX-010, EX-019 (Win32), EX-019 (Win64*) |
| Heap buffer overflow (stale allocation) | 2 | EX-002, EX-012 |
| Use-after-free → callback | 2 | EX-006, EX-019 (Win64) |
| Template injection → code execution | 2 | EX-015, EX-018 |
| COM / IPC callback | 1 | EX-001 |
| Symlink race → out-of-bounds write | 1 | EX-003 |
| Type confusion → function pointer overwrite | 1 | EX-004 |
| ADS name normalization bypass | 1 | EX-007 |
| HTTP request queue desync | 1 | EX-009 |
| Unconditional verify → priv esc | 1 | EX-013 |
| Container namespace bypass | 1 | EX-014 |
| Image trust → confused deputy | 1 | EX-016 |
| Search path hijack | 1 | EX-017 |
| Server-pushed config bypass | 1 | EX-020 |
| URL token expansion → exfiltration | 1 | EX-021 |
| Unsigned wraparound → oversized payload | 1 | EX-022 |
| Case-sensitive env var check → bypass | 1 | EX-023 |

---

## 9. Entry Lookup by Name

| Name / Keyword | ID |
|----------------|----|
| AnyDesk, printer, pipe, COM | EX-001 |
| VLC, VP9, resolution, stale allocation | EX-002 |
| Docker cp, TOCTOU, symlink, container | EX-003 |
| PHP 8.5.7, StreamBucket, SOAP, zend | EX-004 |
| objdump, DLX, binutils, BFD | EX-005 |
| c-ares, ares_getaddrinfo, EDNS, UAF | EX-006 |
| 7-Zip, RAR5, MotW, Zone.Identifier | EX-007 |
| Ghidra, Swift demangler, TraceRMI | EX-008 |
| nghttp2, nghttpx, HTTP Upgrade, smuggling | EX-009 |
| libssh2, CVE-2026-55200, packet length, wrap | EX-010 |
| RustDesk, relay, session downgrade, FileTransfer | EX-011 |
| FFmpeg, RASC, DLTA, decode_dlta, PAL8 | EX-012 |
| MyBB, Admin CP, verify_usergroup | EX-013 |
| Gitea, act_runner, container, --privileged | EX-014 |
| Floci, API Gateway, VTL, Velocity, IAM | EX-015 |
| System Informer, phsvc, ALPC, Authenticode | EX-016 |
| ImageMagick, Ghostscript, gswin64c | EX-017 |
| Lunar Client, Modrinth, Electron, rehypeRaw | EX-018 |
| libssh2, publickey, SSH2_REALLOC | EX-019 |
| OpenVPN Connect, echo, script, disconnect | EX-020 |
| Firefox, Smart Window, AI, Tools.sys.mjs | EX-021 |
| Nmap, IPv6, extension header, wraparound | EX-022 |
| Flowise, MCP, env var, NODE_OPTIONS | EX-023 |

---

## 10. Quick Reference Card

```text
CRITICAL (7)     HIGH (14)                   MEDIUM (2)
┌──────────┐    ┌──────────────────────┐    ┌──────────┐
│ EX-004   │    │ EX-001               │    │ EX-002   │
│ EX-006   │    │ EX-003               │    │ EX-022   │
│ EX-010   │    │ EX-005  EX-011       │    └──────────┘
│ EX-012   │    │ EX-007  EX-013       │
│ EX-015   │    │ EX-008  EX-014       │    BY CWE:
│ EX-018   │    │ EX-009  EX-016       │    ┌──────────┐
│ EX-019   │    │ EX-017  EX-020       │    │ CWE-190  │
└──────────┘    │ EX-021  EX-023       │    │ ×3       │
                └──────────────────────┘    │ CWE-862  │
                                            │ ×4       │
BY LANGUAGE:                                │ CWE-787  │
┌──────────┬──────┐                        │ ×2       │
│ C/C++    │  8   │                        │ CWE-178  │
│ JS/TS    │  3   │                        │ ×2       │
│ PHP      │  2   │                        │ CWE-416  │
│ Go       │  2   │                        │ ×2       │
│ Java     │  2   │                        └──────────┘
│ Rust     │  1   │
│ C#       │  1   │
└──────────┴──────┘
```

---

## 11. External References

| Resource | Link |
|----------|------|
| Exploitarium PoC Repository | https://github.com/bikini/exploitarium |
| objdump OOB-W (EX-005) — independent prior discovery by 4D4J | https://github.com/4D4J/objdump-Out-Of-Bounds-write |
| CVE-2026-55200 Record | https://www.cve.org/CVERecord?id=CVE-2026-55200 |
| libssh2 Fix Commit | https://github.com/libssh2/libssh2/commit/97acf3dfda80c91c3a8c9f2372546301d4a1a7a8 |
| nghttp2 Fix Commit | https://github.com/nghttp2/nghttp2/commit/ab28105c4a0197da24f8bfc414bc116055249e1e |
| RustDesk Source | https://github.com/rustdesk/rustdesk |
| c-ares Source | https://github.com/c-ares/c-ares |
| FFmpeg Source | https://github.com/FFmpeg/FFmpeg |

---

*Generated 2026-06-28. 23 entries. Cross-referenced by severity, type, language, CWE, product, and discovery method.*
