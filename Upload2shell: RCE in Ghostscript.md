Upload2Shell (CVE-2026-125396)

Critical Ghostscript Use-After-Free (UAF) Vulnerability Leading to Remote Code Execution (RCE)

Severity: Critical
Vulnerability Type: Use-After-Free (UAF), Type Confusion, Sandbox Bypass, Remote Code Execution (RCE)
Affected Component: Ghostscript Type 1 Font Loader
CVE ID: CVE-2026-125396

⸻

1. Executive Summary

Upload2Shell (CVE-2026-125396) is a critical Use-After-Free (UAF) vulnerability in Ghostscript’s Type 1 font loader. The vulnerability may allow remote attackers to bypass Ghostscript’s security sandbox and achieve Remote Code Execution (RCE).

Applications and libraries that rely on Ghostscript for document and image processing may be exposed to this vulnerability. Common examples include:

* ImageMagick
* PHP Imagick
* Python Pillow (when configured with a Ghostscript-backed processing workflow)
* Applications that process PostScript-based files

An unauthenticated attacker may exploit a vulnerable application by uploading a specially crafted image or document through an exposed file-upload endpoint, provided the application processes the file using a vulnerable Ghostscript installation.

⸻

2.  Details

2.1 Font Loader Type Confusion

The root vulnerability resides in the .putgstringcopy helper within Ghostscript’s internal PostScript library:

Resource/Init/gs_fonts.ps

The helper relies on a privileged internal operator called .forceput to write into protected font dictionaries.

During execution, .putgstringcopy copies an operand string from the PostScript stack without adequately validating its type.

An attacker can exploit this behavior through the following sequence:

1. Register a malicious Type 1 font.
2. Hijack the PostScript error handler using errordict /typecheck.
3. Manipulate the operand stack to substitute a local array for the expected string.
4. Trigger a type-check failure.
5. Use the error handler to recover execution with a manipulated operand stack.
6. Arrange the stack so that attacker-controlled dictionary, key, and value operands are passed to the subsequent .forceput operation.

This behavior can bypass interpreter security constraints and provide an arbitrary dictionary-write primitive.

2.2 Exploit Chain: Native Memory Corruption and Sandbox Bypass

The attacker can use the dictionary-write primitive to exploit a lifetime mismatch between local and global virtual memory spaces within the Ghostscript interpreter.

The exploitation process involves:

1. Memory Lifetime Manipulation: A local array is stored inside a global dictionary (systemdict), allowing its reference to survive after a PostScript restore operation reclaims the local object’s memory.
2. Use-After-Free Condition: When the freed memory is subsequently reused by newly allocated integer arrays, the dangling global reference and the new live object can point to the same physical memory region.
3. Memory Aliasing: The attacker exploits this aliasing condition to inspect and manipulate memory.
4. Native Structure Manipulation: On 64-bit systems, the attacker constructs a fake writable string reference over the native device structure pointer (gx_device).
5. Pointer Traversal: The attacker traverses internal pointers to locate the native path-control structure (gs_lib_ctx_core_t).
6. Sandbox Bypass: By modifying path_control_active (reported offset: 156) and writing null bytes into the relevant memory field, the attacker can disable the in-memory path restrictions associated with the -dSAFER sandbox.
7. Remote Code Execution: With the sandbox restrictions bypassed, PostScript file-piping operations, such as %pipe%, may be used to execute operating-system commands.

Security Impact: Successful exploitation may result in arbitrary operating-system command execution under the privileges of the vulnerable application or service account.

⸻

3. Affected Products and Components

The vulnerability originates in upstream Ghostscript. Consequently, applications, libraries, containers, and operating system distributions that bundle or depend on vulnerable Ghostscript versions may be affected.

Potentially affected components include:

Component	Potential Exposure
Ghostscript	Directly affected component
ImageMagick	May invoke Ghostscript for PostScript and PDF processing
PHP Imagick	May expose vulnerable processing through uploaded files
Python applications	May be affected when their image/document processing workflow delegates to Ghostscript
WordPress	Potential exposure through vulnerable image/document processing workflows
Roundcube	Potential exposure through attachment conversion and rendering workflows
Docker containers	May remain vulnerable if they contain outdated Ghostscript binaries
CUPS / IPP printing services	Potential exposure through workflows that process untrusted PostScript documents

Important: Actual exposure depends on the installed Ghostscript version, downstream patches, application configuration, and whether untrusted PostScript-based content reaches the vulnerable processing component.

⸻

4. Recommendations and Mitigation

4.1 Upgrade Upstream Ghostscript (Primary Mitigation)

The primary recommendation is to upgrade Ghostscript to a patched release.

* Upgrade upstream Ghostscript to version 10.08.0 or higher.
* For operating system distribution packages, verify that the vendor has incorporated the relevant security fix.
* Do not rely exclusively on upstream version numbers; distributions may backport security patches without adopting the latest upstream version.

Ubuntu

Ensure that systems include the security updates associated with:

USN-8949-1

Example target package version for Ubuntu 24.04 LTS:

10.02.1~dfsg1-0ubuntu7.10

Debian 13

Upgrade Ghostscript to:

10.05.1~dfsg-1+deb13u2

Or a later patched release.

Containerized Environments

Special attention is required for Docker and other containerized deployments.

* Update Ghostscript packages inside container images.
* Rebuild affected Docker images.
* Redeploy the updated containers.
* Verify that no outdated Ghostscript binaries remain in application images.

Note: Updating Ghostscript on the host operating system does not automatically patch Ghostscript binaries bundled inside containers.

4.2 Update Downstream Applications and Wrappers

Ensure that applications relying on Ghostscript or processing untrusted attachments are updated.

WordPress

Update WordPress Core to one of the following releases or newer patched releases:

* WordPress 7.0.4
* WordPress 6.9.7

These releases are identified as containing the CVE-2026-65640 mitigation.

Roundcube

Ensure Roundcube is updated beyond:

* Version 1.7.2
* Version 1.6.17

Alternatively, implement the CVE-2026-114727 mitigation to prevent unsafe attachment conversion before rendering.

Note: Verify the applicable vendor security advisories and patched release information before deployment.

4.3 Implement Strict ImageMagick Security Policies

If Ghostscript cannot be patched immediately, restrict ImageMagick from delegating document processing to PostScript interpreters.

Locate the ImageMagick security policy file. Common locations include:

* /etc/ImageMagick-7/policy.xml
* /etc/ImageMagick-6/policy.xml

Add or verify the following restrictions:

<policymap>
  <policy domain="coder" rights="none" pattern="PS" />
  <policy domain="coder" rights="none" pattern="EPS" />
  <policy domain="coder" rights="none" pattern="PDF" />
  <policy domain="coder" rights="none" pattern="XPS" />
</policymap>

These restrictions disable ImageMagick’s ability to process the specified formats through its corresponding coders.

Expected Outcome:

* Prevents ImageMagick from processing PostScript files.
* Restricts EPS and PDF processing through the affected coders.
* Reduces the risk of malicious file uploads triggering vulnerable Ghostscript functionality.

Important: Test the policy against application workflows before production deployment, as legitimate PDF and PostScript processing may stop working.

4.4 Apply Least-Privilege and OS-Level Hardening

In addition to patching, implement operating-system-level security controls to limit the impact of successful exploitation.

A. IPP Print Queues

For CUPS and IPP printing infrastructure:

* Enforce authentication on shared network printing queues.
* Restrict access to trusted networks and authorized clients.
* Disable unnecessary remote printing services.
* Prevent unauthenticated users from submitting arbitrary PostScript documents.

B. Web Server and Printing Service Accounts

Restrict the system execution capabilities and permissions of service accounts such as:

* www-data
* lp

Recommended controls:

* Apply AppArmor or SELinux policies.
* Use seccomp restrictions where appropriate.
* Restrict access to unnecessary filesystem paths.
* Prevent service accounts from executing unauthorized system shells.
* Apply strict filesystem permissions.
* Limit network access and unnecessary system capabilities.

Expected Outcome: These controls reduce the potential impact of exploitation by limiting the privileges and resources available to compromised services.

⸻

5. Security Checklist

Use the following checklist to validate mitigation activities.

* [ ]	Identify all installed Ghostscript versions.
* [ ]	Identify applications and libraries that invoke Ghostscript.
* [ ]	Upgrade Ghostscript to a patched version.
* [ ]	Verify Ubuntu/Debian security package updates.
* [ ]	Rebuild and redeploy affected Docker images.
* [ ]	Update WordPress Core to an applicable patched release.
* [ ]	Update Roundcube to an applicable patched release.
* [ ]	Review and restrict ImageMagick policy.xml.
* [ ]	Disable unnecessary PS, EPS, PDF, and XPS coders where appropriate.
* [ ]	Enforce authentication on shared CUPS/IPP printing queues.
* [ ]	Apply AppArmor, SELinux, or seccomp restrictions.
* [ ]	Restrict permissions for www-data and lp service accounts.
* [ ]	Verify that vulnerable Ghostscript binaries are no longer accessible.
* [ ]	Test image and document upload workflows after mitigation.
* [ ]	Monitor application logs for suspicious file-processing activity.

⸻

6. Conclusion

Upload2Shell (CVE-2026-125396) represents a critical security risk for environments that process untrusted PostScript-based files using vulnerable Ghostscript installations.

The combination of a font-loader type-confusion issue, memory lifetime manipulation, and sandbox bypass may allow attackers to escalate a seemingly harmless file-upload operation into operating-system command execution.

Organizations should prioritize upgrading Ghostscript, updating affected downstream applications, restricting ImageMagick’s PostScript-related coders, and applying least-privilege security controls.

Primary Action: Patch Ghostscript across all affected hosts and container images. Treat ImageMagick restrictions and OS-level sandboxing as additional defense-in-depth measures, not substitutes for applying the security update.

⸻

Document Classification: Security Advisory
Vulnerability: CVE-2026-125396
Recommended Priority: Critical
Primary Mitigation: Upgrade Ghostscript to a verified patched release.