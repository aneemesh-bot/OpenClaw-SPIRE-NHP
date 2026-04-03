# The Proposed "Non-Human Persona" (NHP) Framework Daemon

Investigating the failure of traditional Identity & Access Management (IAM) in autonomous systems like OpenClaw is a critical research frontier. Traditional IAM is designed for two types of actors: humans (who use MFA and judgment) and service accounts (which are deterministic and predictable). OpenClaw agents fit neither category—they are non-deterministic and highly autonomous, yet they often "borrow" human credentials, leading to a total collapse of accountability.

To solve these issues, your prototype can propose an NHP Framework. Unlike a simple service account, an NHP is a dynamic identity that bridges the gap between the human owner and the autonomous agent.

| **Component**            | **Function**                                                 | **Technical Implementation**                                 |
| ------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Unique Agent-ID**      | Distinguishes the *instance* from the *owner*.               | X.509 certificates with metadata.                            |
| **Delegated-By Trace**   | Links every action back to the authorizing human.            | Signed JWT (JSON Web Tokens) with a `sub` (agent) and `act_as` (human) claim. |
| **Intent-Based Scoping** | Permissions change based on the *task*, not just the identity. | **ABAC (Attribute-Based Access Control)** triggered by the agent’s current goal. |
| **Ephemeral Lifecycles** | Identities exist only for the duration of a specific mission. | Short-lived SPIFFE/Spire identities (minutes, not days).     |

To refine the **Non-Human Persona (NHP)** framework, we need to move from conceptual "labels" to a hard-coded security architecture. 
Two aspects—**Binding** and **Scoping**—act as the lock and the key, respectively.

---

### 1. Cryptographic Binding: Rooting the "Soul" in Hardware
Traditional IAM fails because an agent’s "identity" is often just a stolen session cookie. 
We need to cryptographically bind the OpenClaw process to a specific hardware root of trust.

* **TPM-Backed Attestation:** Every OpenClaw instance should generate a key pair inside the host's **Trusted Platform Module (TPM)**. This ensures the identity cannot be "cloned" to another machine. For nowm this can be simulated using software-generated keys to simulate TPM RNG.
* **SPIFFE/SPIRE for Workload Identity:** Instead of static API keys, use the **SPIFFE** (Secure Production Identity Framework for Everyone) standard. The agent receives a short-lived **SVID** (SPIFFE Verifiable Identity Document).
    * *Mechanism:* The OpenClaw daemon proves its "health" (checksum of its source code and `SOUL.md` file) to a SPIRE server, which then issues a 15-minute X.509 certificate.
* **The Owner Signature:** Every request made by the agent must be co-signed. The header would look like a **Multi-Signature JWT**, requiring:
    1.  The Agent’s Private Key (Proof of Instance).
    2.  The User’s Session Token (Proof of Delegation).

---

### 2. Policy-Based Scoping: Just-In-Time (JIT) Intent Guardrails
Static permissions (RBAC) are dangerous for agents. If you give an agent "Contributor" access to a repo, it can delete the main branch. We need **Intent-Based Access Control (IBAC)**.

* **The Intent Parser:** Before OpenClaw executes a tool, a "Policy Proxy" (using **Open Policy Agent / OPA**) intercepts the request. It asks: *"Does the current goal in `MEMORY.md` match this action?"*
* **Dynamic Scoping:**
    * **Scenario A:** Agent goal is "Researching competitors."
        * *Policy:* Access to `Browser_Tool` (Read-only), `Filesystem_Tool` (Write to `/tmp/research` only).
    * **Scenario B:** Agent goal is "Updating the database."
        * *Policy:* Access to `SQL_Tool` (Write), but requires a **Human-in-the-Loop (HITL)** trigger for `DROP` or `DELETE` commands.

**The "Trust-but-Verify" Logic:**
We can define the policy logic using a simple conditional relationship. For an action $A$ to be permitted, it must satisfy:
$$P(A) = (Identity_{Valid} \land Attestation_{Success}) \land (Intent(A) \in Authorized\_Scope)$$



---

### Refined NHP Summary Table

| Feature | Old Method (Service Account) | New NHP Method (OpenClaw) |
| :--- | :--- | :--- |
| **Credential** | Long-lived API Key | Short-lived, Hardware-bound SVID |
| **Authority** | Static Role (Admin/User) | Dynamic "Mission" Scope |
| **Verification** | Simple Auth | Mutual TLS + Code Integrity Check |
| **Accountability** | Shared Secret | Cryptographic Trace to Human Owner |

---

### Integrating the Two
The "Magic" happens when these two converge: The **Cryptographic Binding** proves *who* the agent is and that its code hasn't been tampered with, while **Policy Scoping** ensures it stays within the guardrails of its current mission.

Focusing on the **infrastructure level** moves us away from the "soft" reasoning of the LLM and into the "hard" reality of the OS kernel and hardware. This is the "plumbing" that ensures an agentic system like OpenClaw doesn't accidentally—or maliciously—flood the digital basement.

At this level, we are moving from **Identity as a Secret** (a key or password) to **Identity as a State** (a verifiable condition of the system).

------

### 1. Hardware-Rooted Attestation (The Binding)

The core infrastructure challenge is ensuring that the OpenClaw process running on a server is the **exact, untampered binary** authorized by the enterprise.

#### **The TPM + SPIRE Workflow**

1. **Measured Boot:** As OpenClaw starts, the host’s **Trusted Platform Module (TPM)** measures the binary’s hash and stores it in a **Platform Configuration Register (PCR)**.
2. **Workload Attestation:** A SPIRE (SPIFFE Runtime Environment) agent running on the host queries the kernel for the process ID (PID) of the OpenClaw instance.
3. **The "Who Are You?" Check:** SPIRE doesn't just ask the agent its name; it performs **Attestation**. It checks the binary hash against a "known good" value in the enterprise's policy.
4. **SVID Issuance:** If the attestation succeeds, SPIRE mounts a short-lived **SVID (SPIFFE Verifiable Identity Document)** into the agent’s memory space. This is a certificate that the agent uses to prove its NHP identity to other services (like a database or a web proxy).

------

### 2. Kernel-Level Enforcement (The Scoping)

Once the identity is bound, we need a way to enforce the "Mission Scope" at the system call level. If an OpenClaw agent is told to "Browse the web," the infrastructure should physically prevent it from calling `execve()` on a shell or `connect()` to an internal database.

#### **Implementation: eBPF + LSM (Linux Security Modules)**

By 2026, **eBPF (extended Berkeley Packet Filter)** has become the standard for "Agentic Firewalls." You can implement a security monitor that hooks directly into the Linux kernel's security hooks (LSM).

- **The Hook:** An eBPF program is attached to syscalls like `sys_connect` or `sys_openat`.
- **The Context:** When OpenClaw attempts an action, the eBPF program looks up the **Task ID** and maps it to the NHP's current **Mission Profile**.
- **The Verdict:** If the NHP is in "Research Mode" but attempts to open `/etc/shadow`, the kernel blocks the call before it even reaches the filesystem.

#### **Formalizing the Verification Logic**

We can define the infrastructure's "Allow" condition ($L_{Allow}$) as a function of the measured state ($M$) and the dynamic mission entropy ($E$):

$$L_{Allow}(A) = \begin{cases} 1 & \text{if } \text{Attest}(M) \land \text{Valid}(SVID) \land (A \subseteq \text{Scope}(E)) \\ 0 & \text{otherwise} \end{cases}$$

Where:

- $M$ is the TPM-measured binary state.
- $SVID$ is the SPIFFE-issued identity certificate.
- $Scope(E)$ is the kernel-enforced permission set based on the current mission goal.

------

### 3. The "State Transfer" Problem

A major hurdle for your research will be **How the LLM communicates intent to the Kernel.** In a traditional setup, the LLM just says "I want to do X." In your infrastructure-heavy NHP framework, we need a **Policy Translator**:

1. **LLM** outputs a "Goal" (e.g., "Analyze the Q3 spreadsheet").
2. **Orchestrator** (OpenClaw) requests a **Scope Expansion** from the NHP Identity Provider.
3. **Identity Provider** validates the request and pushes a new **eBPF Map** to the kernel.
4. **Kernel** now allows the specific PID to access the spreadsheet file, but *nothing else*.

We have to focus on **SPIRE-based attestation**.



Architecting the **SPIRE Trust Bundle** for an OpenClaw-based Non-Human Persona (NHP) moves the security boundary from the application layer down to the infrastructure. In this model, the "Trust Bundle" is the root of all authority—it is the collection of CA certificates that allow your autonomous agent to prove its identity to databases, cloud APIs, and other agents without ever touching a static password.

Here is the architectural breakdown for a 2026-ready NHP infrastructure.

------

### 1. The Trust Domain Hierarchy

To prevent "identity sprawl," we first define a structured SPIFFE ID namespace. An OpenClaw agent isn't just a generic "AI"; it is a specific persona with a specific mission.

- **Trust Domain:** `spiffe://enterprise.com`
- **Persona Path:** `spiffe://enterprise.com/nhp/openclaw/finance-auditor`
- **Instance ID:** `spiffe://enterprise.com/nhp/openclaw/finance-auditor/inst-9921`

The **Trust Bundle** sits at the top of this hierarchy. It contains the public keys of the SPIRE Server(s) authorized to sign certificates for these IDs.

------

### 2. Multi-Cloud Federation (The Bundle Exchange)

OpenClaw agents often operate across hybrid environments (e.g., a "Brain" in AWS and "Hands" on an on-prem workstation). To maintain a single NHP identity, we use **SPIRE Federation**.

- **The Mechanism:** Instead of a single massive CA, you have separate SPIRE Servers for each environment (AWS, Azure, On-Prem).
- **Trust Bundle Exchange:** The AWS SPIRE Server and the On-Prem SPIRE Server "swap" bundles via a **Bundle Endpoint**.
- **Result:** When the OpenClaw agent in AWS tries to access an on-prem SQL database, the database checks its local trust bundle, finds the AWS public key, and verifies the agent's SVID instantly.

$$Trust(A, B) \iff \text{Bundle}_B \in \text{Authorized\_Federation}(A)$$

------

### 3. Distribution: The "Bottom Turtle" Problem

How does the OpenClaw process get the bundle without a "bootstrap" secret? We solve this at the kernel level.

1. **Workload API:** The SPIRE Agent exposes a **Unix Domain Socket (UDS)** on the host.
2. **No-Auth Retrieval:** OpenClaw connects to the socket. It doesn't send a password.
3. **Kernel Interrogation:** The SPIRE Agent uses `SO_PEERCRED` to identify the caller's PID. It then inspects `/proc/<PID>/exe` to ensure the binary hash matches the authorized OpenClaw version.
4. **Bundle Injection:** Once verified, the Agent pushes the **Trust Bundle** and the **SVID** (private key/cert) directly into the agent’s memory or a temporary in-memory filesystem (`tmpfs`).

------

### 4. Security Lifecycle: Rotation and Revocation

In 2026, the primary threat to NHPs is "model hijacking" (Prompt Injection). If the agent’s "reasoning" is compromised, the infrastructure must be able to "burn" the identity immediately.

- **Short-Lived SVIDs:** Set the TTL (Time-To-Live) for agent certificates to **5–15 minutes**.
- **Ghost Revocation:** If the eBPF monitor detects the agent attempting to access forbidden system files, it sends a signal to the SPIRE Server.
- **Immediate Pruning:** The SPIRE Server removes the registration entry for that specific `inst-9921`. When the agent tries to refresh its certificate 5 minutes later, it is denied, effectively "killing" its network access.

------

### 5. Technical Specification Summary

| **Component**     | **Infrastructure Specification**                             |
| ----------------- | ------------------------------------------------------------ |
| **Trust Store**   | Hardware Security Module (HSM) or AWS KMS (Asymmetric).      |
| **Bundle Format** | Standardized JWT-SVID for cloud APIs; X.509-SVID for mTLS.   |
| **Propagation**   | Periodic polling of the `.well-known/spiffe-bundle-endpoint`. |
| **Enforcement**   | Ghostunnel or Envoy sidecar to handle the mTLS handshake on behalf of OpenClaw. |

### The "Sovereign" Identity Logic

By architecting the bundle this way, the OpenClaw agent becomes a **Sovereign Workload**. It no longer relies on the human owner's credentials. If the human owner leaves the company, the agent's NHP identity (and its hardware-bound trust) remains intact, governed by the enterprise SPIRE policy rather than an individual's OAuth token.
