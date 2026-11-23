🚨 Upload2Shell

Critical Ghostscript Vulnerability — CVE-2026-125396

<p align="center">
  **CRITICAL SECURITY ADVISORY**
</p>

Advisory Detail	Information
CVE ID	CVE-2026-125396
Vulnerability	Use-After-Free (UAF) / Type Confusion
Affected Component	Ghostscript Type 1 Font Loader
Potential Impact	Sandbox Bypass & Remote Code Execution
Attack Vector	Malicious File Upload
Authentication	Potentially Unauthenticated
Severity	🔴 Critical

⸻

1. Executive Summary

Upload2Shell is a critical vulnerability in Ghostscript’s Type 1 font loader that may allow remote attackers to bypass the interpreter’s security sandbox and execute arbitrary operating-system commands.

The vulnerability is particularly concerning because Ghostscript is commonly integrated into image and document-processing workflows.

Applications and libraries such as:

* ImageMagick
* PHP Imagick
* Python-based image-processing applications
* Document conversion and rendering services

may indirectly expose vulnerable Ghostscript functionality when processing untrusted PostScript-based files.

<blockquote>
⚠️ **Security Impact**

An attacker may be able to exploit an exposed file-upload or document-processing endpoint by submitting a specially crafted file, potentially resulting in remote code execution under the privileges of the vulnerable service.

</blockquote>

2. Technical Deep Dive

2.1 Root Cause — Font Loader Type Confusion

The vulnerability originates in Ghostscript’s internal PostScript library:

Resource/Init/gs_fonts.ps

The affected helper is:

.putgstringcopy

This helper relies on the privileged internal operator .forceput to modify protected font dictionaries.

The underlying issue involves insufficient operand-type validation during string-copy processing.

Attack mechanism:

1. A malicious Type 1 font manipulates the PostScript interpreter’s execution flow.
2. The attacker hijacks the errordict /typecheck error handler.
3. An array is substituted where a string is expected.
4. A type-check exception is triggered.
5. Error recovery resumes with a manipulated operand stack.
6. Attacker-controlled operands are passed to .forceput.

Result: An attacker may obtain an arbitrary dictionary-write primitive that bypasses intended interpreter security restrictions.

2.2 Exploitation — Use-After-Free and Memory Aliasing

The next stage exploits a lifetime mismatch between local and global virtual memory spaces.

<details>
<summary><strong>View exploitation stages</strong></summary>

Stage 1 — Dangling Reference

A local array is stored in a global dictionary (systemdict).

Stage 2 — Memory Reclamation

A PostScript restore operation reclaims the local object’s memory while the global reference remains.

Stage 3 — Memory Aliasing

Newly allocated integer arrays reuse the reclaimed memory region, creating an alias between the dangling reference and a live object.

Stage 4 — Native Memory Manipulation

On 64-bit systems, the attacker leverages the aliasing condition to construct a fake writable string reference over native structure memory.

Stage 5 — Pointer Traversal

The attacker follows internal pointers associated with gx_device to locate the path-control structure gs_lib_ctx_core_t.

</details>

2.3 Sandbox Bypass and Remote Code Execution

The reported exploitation chain targets the native path-control field:

path_control_active

Reported offset:

156

By modifying this field in memory, the attacker may disable path restrictions associated with Ghostscript’s -dSAFER sandbox.

The resulting security impact may include:

* Bypassing file access restrictions.
* Accessing resources outside permitted paths.
* Executing operating-system commands.
* Achieving remote code execution through PostScript file-piping functionality.

Example of the affected PostScript mechanism: %pipe%

<blockquote>
🔴 **Final Impact:** A vulnerable document or image-processing service may become a remote code-execution entry point.
</blockquote>

⸻

3. Affected Products & Attack Surface

The vulnerability resides in upstream Ghostscript. Consequently, downstream applications that bundle, invoke, or depend on vulnerable Ghostscript installations may be exposed.

Product / Component	Potential Exposure
Ghostscript	Direct vulnerability
ImageMagick	PostScript/PDF delegation
PHP Imagick	Image-processing workflows
Python applications	Ghostscript-backed rendering workflows
WordPress	Image and document processing
Roundcube	Attachment conversion and rendering
Docker containers	Bundled vulnerable Ghostscript binaries
CUPS / IPP	Untrusted PostScript print submissions

Important: Actual exposure depends on the installed version, vendor patches, configuration, and whether untrusted content reaches the vulnerable Ghostscript processing path.

⸻

4. Recommended Mitigations

🔴 4.1 Upgrade Ghostscript — Primary Mitigation

Upgrade Ghostscript to:

Version 10.08.0 or higher, as specified in the supplied advisory.

For distribution-managed systems, verify vendor security updates and backported fixes rather than relying solely on upstream version numbers.

Ubuntu

Security advisory reference:

USN-8949-1

Example target package:

10.02.1~dfsg1-0ubuntu7.10

Debian 13

Recommended package:

10.05.1~dfsg-1+deb13u2

Or a later patched release.

Docker and Containerized Applications

<blockquote>
⚠️ Updating the host operating system does not automatically update Ghostscript binaries inside Docker containers.
</blockquote>

Required actions:

* Update Ghostscript in the container image.
* Rebuild affected images.
* Redeploy running containers.
* Verify installed package versions inside each container.

4.2 Update Downstream Applications

Application	Recommended Version / Mitigation
WordPress	7.0.4, 6.9.7, or applicable newer patched release
Roundcube	Beyond 1.7.2 / 1.6.17, or applicable mitigation

WordPress: The supplied advisory identifies CVE-2026-65640 as a related mitigation.

Roundcube: The supplied advisory identifies CVE-2026-114727 as a related mitigation for unsafe attachment conversion before rendering.

Verify the relevant vendor advisories before deployment.

4.3 Restrict ImageMagick PostScript Processing

If Ghostscript cannot be immediately patched, restrict ImageMagick from invoking PostScript-related coders.

Configuration file locations:

/etc/ImageMagick-7/policy.xml
/etc/ImageMagick-6/policy.xml

Recommended security policy:

<policymap>
  <policy domain="coder" rights="none" pattern="PS" />
  <policy domain="coder" rights="none" pattern="EPS" />
  <policy domain="coder" rights="none" pattern="PDF" />
  <policy domain="coder" rights="none" pattern="XPS" />
</policymap>

Security benefits:

* Blocks processing through the specified ImageMagick coders.
* Reduces exposure to malicious PostScript-based uploads.
* Prevents affected workflows from delegating these formats to Ghostscript through ImageMagick.

Note: This may disable legitimate PDF, EPS, PS, and XPS processing. Test application compatibility before production deployment.

4.4 Apply Least-Privilege Security Controls

Implement OS-level hardening to limit the impact of successful exploitation.

A. CUPS / IPP Printing Infrastructure

* Enforce authentication on shared printing queues.
* Restrict access to trusted networks.
* Disable unnecessary remote printing services.
* Prevent unauthorized PostScript submissions.

B. Web Server and Printing Service Accounts

Apply restrictions to:

www-data
lp

Recommended security controls:

Security Control	Purpose
AppArmor	Restrict application and filesystem access
SELinux	Enforce mandatory access controls
Seccomp	Restrict available system calls
File Permissions	Prevent unauthorized file access
Process Isolation	Limit the impact of service compromise
Network Restrictions	Prevent unnecessary outbound connections

Where operationally feasible, prevent service accounts from executing unauthorized shells or accessing unnecessary system paths.

⸻

5. Security Verification Checklist

Use this checklist during remediation and security validation.

* [ ]	Identify all Ghostscript installations.
* [ ]	Identify vulnerable versions and downstream dependencies.
* [ ]	Upgrade Ghostscript to a verified patched release.
* [ ]	Verify Ubuntu and Debian security updates.
* [ ]	Rebuild and redeploy affected Docker images.
* [ ]	Update WordPress and Roundcube.
* [ ]	Review ImageMagick policy.xml.
* [ ]	Restrict unnecessary PS, EPS, PDF, and XPS processing.
* [ ]	Enforce authentication on CUPS/IPP queues.
* [ ]	Apply AppArmor, SELinux, or seccomp restrictions.
* [ ]	Review www-data and lp service permissions.
* [ ]	Validate file-upload and document-rendering workflows.
* [ ]	Monitor application logs for suspicious processing activity.
* [ ]	Confirm that vulnerable Ghostscript binaries are no longer in use.

⸻

6. Priority Remediation Matrix

Priority	Recommended Action
🔴 Critical	Upgrade Ghostscript
🔴 Critical	Rebuild affected containers
🟠 High	Restrict ImageMagick PostScript coders
🟠 High	Update downstream applications
🟡 Medium	Harden service accounts
🟡 Medium	Secure CUPS/IPP printing infrastructure
🟢 Ongoing	Monitor logs and validate configurations

⸻

7. Conclusion

Upload2Shell highlights the security risks associated with processing untrusted document and image formats through vulnerable rendering engines.

The reported combination of Type 1 font-loader type confusion, memory lifetime manipulation, and sandbox bypass creates a potentially serious attack path from file upload to operating-system command execution.

Organizations should prioritize:

1. Patch: Upgrade all vulnerable Ghostscript installations.
2. Restrict: Disable unnecessary PostScript-related processing.
3. Harden: Apply least-privilege controls to application services.
4. Verify: Audit hosts, containers, and downstream dependencies.

<blockquote>
🔐 **Security Recommendation**

Do not rely on sandbox restrictions alone when processing untrusted PostScript files. Apply security updates and defense-in-depth controls across the entire document-processing pipeline.

</blockquote>

⸻

Advisory Information

Field	Value
Advisory Name	Upload2Shell
CVE	CVE-2026-125396
Category	Application Security
Primary Component	Ghostscript
Severity	Critical
Recommended Response	Immediate remediation

Disclaimer: This document is based on the supplied technical advisory. CVE identifiers, exploit details, affected releases, package versions, and related downstream mitigations should be independently validated against official vendor security advisories before publication.