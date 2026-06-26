# GuardianAI Alignment: NIST AI Risk Management Framework (RMF)

**Date:** April 2026
**Target:** GuardianAI Enterprise Suite
**Objective:** Provide a conformance report demonstrating how GuardianAI allows organizations to fulfill the core functions of the NIST AI Risk Management Framework (RMF).

---

## 1. GOVERN (Cultivating a culture of risk management)
**NIST Requirement:** Organizations must establish policies, roles, and accountability for AI system risks.
**How GuardianAI Delivers:**
* **Centralized RBAC:** GuardianAI enforces strict multi-tenant Role-Based Access Control via JWT.
* **Immutable Audit Logs:** Every system change, threshold update, or login is logged for SOC 2 Type II audit readiness.
* **Global Visibility:** The GuardianAI Admin Dashboard acts as the single pane of glass for executives to govern AI usage across the entire enterprise.

## 2. MAP (Contextualizing and identifying AI risks)
**NIST Requirement:** Organizations must contextually understand and map out the specific risks (e.g., bias, security, privacy) their AI poses.
**How GuardianAI Delivers:**
* **Real-Time Threat Breakdown:** The GuardianAI telemetry engine categorizes all traffic into distinct threat vectors (Prompt Injections, PII Leaks, Base64 Obfuscation).
* **Differential Privacy (DP) Analytics:** Allows the mapping of user trends and threat frequencies across the organization without violating GDPR or the EU AI Act.

## 3. MEASURE (Assessing, analyzing, and tracking AI risks)
**NIST Requirement:** Organizations must employ quantitative and qualitative metrics to measure AI risks.
**How GuardianAI Delivers:**
* **Dashboard Analytics:** Calculates precise, mathematical metrics including Total Block Rate, Fast-Path Overhead Latency, and Upstream Response Times.
* **Reproducible Benchmarks:** GuardianAI provides built-in benchmarking scripts (Locust, Chaos tests, JailbreakBench JSON exporters) allowing security teams to measure efficacy continuously.

## 4. MANAGE (Prioritizing and acting upon AI risks)
**NIST Requirement:** Organizations must implement mechanisms to actively mitigate, monitor, and respond to identified risks.
**How GuardianAI Delivers:**
* **Sub-40ms Threat Mitigation:** Acts as an active firewall, physically blocking identified risks (like Jailbreaks or SSN leaks) in milliseconds before they cause harm.
* **Configurable Thresholds:** Allows admins to adjust security strictness on the fly (e.g., turning on/off strict PII masking) depending on the assessed risk level.
* **Fail-Open / Fail-Closed Circuit Breakers:** Built-in resilience engineering ensures that if the telemetry database goes offline, the system safely manages the failure state without breaking downstream applications.

---
**Summary:** Deploying GuardianAI instantly provides organizations with the necessary technical scaffolding to achieve full compliance with the NIST AI RMF, significantly accelerating enterprise software procurement.
