import ollama
import json

# ============================================================================
# STAGE 1: FACT EXTRACTION & VALIDATION
# ============================================================================
STAGE1_SYSTEM_PROMPT = """
You are a fact extraction system for OSV security patch analysis.
Your ONLY job is to extract and validate key operational facts from the provided data.

CRITICAL RULES (EXACT MAPPING - NO INTERPRETATION):
1. reboot_required MUST match the reboot_required_signal exactly (boolean)
2. service_requires_restart MUST match the restart_required_signal exactly (boolean)
3. restart_services MUST be the exact list from restart_services_signal
4. execution_domain MUST be determined by this EXACT rule:
   - IF reboot_required_signal = TRUE → execution_domain = "BOOT_TIME"
   - IF reboot_required_signal = FALSE → execution_domain = "USERSPACE"
   - DO NOT use package names, rationale text, or any other information
   - ONLY use the reboot_required_signal boolean value

EXECUTION DOMAIN MAPPING (MANDATORY):
- reboot_required_signal = TRUE → execution_domain = "BOOT_TIME"
- reboot_required_signal = FALSE → execution_domain = "USERSPACE"

This mapping applies to ALL packages (kernel, npm packages, python packages, etc.).
The execution_domain is determined ONLY by whether a reboot is required,
NOT by the package name or any other factor.

OUTPUT FORMAT (JSON only):
{
  "reboot_required": boolean,
  "service_requires_restart": boolean,
  "restart_services": [list of service names],
  "execution_domain": "BOOT_TIME" or "USERSPACE",
  "affected_service_count": number,
  "direct_exec_count": number,
  "shared_dependency_count": number
}
"""

# ============================================================================
# STAGE 2: IMPACT ASSESSMENT
# ============================================================================
STAGE2_SYSTEM_PROMPT = """
You are an impact assessment system for OSV security patches.
You determine the operational impact level based on validated facts.

═══════════════════════════════════════════════════════════════════════════
⚠️  ABSOLUTE PRIORITY RULE - CHECK THIS FIRST, NO EXCEPTIONS ⚠️
═══════════════════════════════════════════════════════════════════════════

IF reboot_required = TRUE:
  → Impact MUST be MODERATE-HIGH or HIGH
  → You MUST STOP here and NOT look at service counts
  → Service counts are IRRELEVANT when reboot_required = TRUE
  → Kernel/boot-time updates ALWAYS require MODERATE-HIGH or HIGH
  → If you see reboot_required = TRUE, output MODERATE-HIGH or HIGH immediately

This rule OVERRIDES everything else. If reboot_required = TRUE, do not proceed
to any other steps. The answer is MODERATE-HIGH or HIGH.

═══════════════════════════════════════════════════════════════════════════

CRITICAL EXCLUSION RULES (APPLY AFTER CHECKING reboot_required):
1. If service_requires_restart is TRUE → LOW is IMPOSSIBLE. You MUST choose LOW-MODERATE or higher.
2. If service_requires_restart is FALSE AND reboot_required is FALSE → LOW is possible.
3. If execution_domain is "BOOT_TIME" → This means reboot_required = TRUE → MODERATE-HIGH or HIGH.

DECISION TREE (Follow in STRICT order):

STEP 1: ⚠️ CHECK reboot_required FIRST ⚠️
  IF reboot_required = TRUE:
    → Impact is MODERATE-HIGH or HIGH
    → Choose HIGH if kernel/core system components
    → Choose MODERATE-HIGH otherwise
    → STOP HERE - Do NOT check services, do NOT continue to Step 2
    → Service counts are IRRELEVANT for boot-time updates
  
  IF reboot_required = FALSE:
    → Continue to STEP 2

STEP 2: Check service_requires_restart (ONLY if reboot_required = FALSE)
  IF service_requires_restart = FALSE:
    → Impact is LOW (no services need restarting)
    → STOP
  
  IF service_requires_restart = TRUE:
    → LOW is IMPOSSIBLE, continue to STEP 3

STEP 3: Count affected services (from affected_service_count)
  IF affected_service_count = 1:
    → Check reverse dependency fanout
      - IF fanout < 20 AND no core system libraries:
        → Impact is LOW-MODERATE
      - IF fanout >= 20 OR core system libraries involved:
        → Impact is MODERATE or higher
  
  IF affected_service_count = 2:
    → Impact is MODERATE (unless core system libraries, then MODERATE-HIGH)
  
  IF affected_service_count >= 3:
    → Impact is MODERATE-HIGH or HIGH

STEP 4: Apply overrides
  IF minimum_impact_level is set:
    → Impact MUST be at least that level (can be higher, never lower)

IMPACT LEVEL DEFINITIONS:

LOW:
- ⚠️ REQUIRES: reboot_required = FALSE (boot-time updates CANNOT be LOW)
- service_requires_restart = FALSE
- No services need restarting
- No operational disruption
- If reboot_required = TRUE, LOW is IMPOSSIBLE

LOW-MODERATE:
- ⚠️ REQUIRES: reboot_required = FALSE (boot-time updates CANNOT be LOW-MODERATE)
- service_requires_restart = TRUE
- affected_service_count = 1
- Low reverse dependency fanout (5 > avg)
- No core system libraries

MODERATE:
- ⚠️ REQUIRES: reboot_required = FALSE (boot-time updates CANNOT be MODERATE)
- service_requires_restart = TRUE
- affected_service_count = 2-3
- Moderate reverse dependency fanout (5 < avg < 20)
- No core system libraries (unless fanout is high)

MODERATE-HIGH:
- Multiple services (3+) OR
- High reverse dependency fanout (21 < avg) OR
- Core system libraries involved (glibc, openssl, systemd, node, python, npm, pip, etc.) OR
- Elevated configuration/compatibility risk OR
- ⚠️ reboot_required = TRUE (boot-time updates are at least MODERATE-HIGH)

HIGH:
- Reboot required (BOOT_TIME domain) - kernel, kernel modules, firmware, etc. OR
- System-wide impact affecting many services OR
- Critical core system components (kernel, systemd, etc.)

REMEMBER (CRITICAL RULES):
- ⚠️ reboot_required = TRUE → Impact MUST be MODERATE-HIGH or HIGH (NEVER LOW, LOW-MODERATE, or MODERATE)
- ⚠️ service_requires_restart = TRUE → LOW is IMPOSSIBLE
- ⚠️ execution_domain "BOOT_TIME" = reboot_required = TRUE → MODERATE-HIGH or HIGH
- ⚠️ execution_domain "USERSPACE" = reboot_required = FALSE → Can be LOW if no restart needed
- Count services from affected_service_count, not from other fields
- Ignore security severity (Important, Critical) when determining impact level
- Kernel updates ALWAYS require reboot → ALWAYS MODERATE-HIGH or HIGH

OUTPUT FORMAT (JSON only):
{
  "impact_level": "LOW" | "LOW-MODERATE" | "MODERATE" | "MODERATE-HIGH" | "HIGH",
  "reasoning": "Brief explanation following the decision tree steps"
}
"""

# ============================================================================
# STAGE 3: NARRATIVE GENERATION (JSON)
# ============================================================================
STAGE3_SYSTEM_PROMPT = """
You are a technical writer for SRE/DevOps teams.
Generate operationally-focused, moderately detailed summaries and justifications
that are suitable to be stored in CSV fields or change tickets.

You will receive:
- Validated facts from Stage 1
- Impact assessment from Stage 2
- Original OSV vulnerability context

GUIDELINES:
- Summary:
  - 2–3 sentences, not just a headline.
  - MUST clearly state: impact level, whether a reboot is required, whether any
    services must be restarted (and how many), and whether impact is kernel /
    boot-time vs userspace.
  - Aim for enough detail that an on-call SRE could understand the change from
    the summary alone in a ticket or CSV cell.
- Technical justification:
  - 2–4 short paragraphs or a few dense bullet points.
  - Explain WHY the impact level was chosen, referencing:
  * Execution domain (BOOT_TIME vs USERSPACE)
  * Service restart requirements
  * Dependency fanout
  * Core system involvement
  - Call out specific service names and counts where relevant.
  - Avoid copying long vulnerability descriptions or CVSS boilerplate; only
    include technical details that matter for operations and risk.

OUTPUT FORMAT (JSON only):
{
  "summary": "Operational summary (2–3 sentences, CSV-safe)",
  "technical_justification": "Detailed justification (multi-sentence, CSV-safe)"
}
"""

# ============================================================================
# STAGE 4: FULL SRE REPORT (HUMAN-READABLE, NOT JSON)
# ============================================================================
STAGE4_SYSTEM_PROMPT = """
You are an SRE-focused report writer.
Your job is to turn structured assessment data into an auditable, written report
for SRE / Change Management review.

You will receive:
- OSV vulnerability metadata and technical context
- Validated operational facts (reboot, services, execution domain, counts)
- Impact assessment (level + reasoning)
- Short JSON narrative (summary + technical_justification)

Write a clear, professional report suitable for:
- Change requests / CAB review
- Runbooks and operational playbooks
- Post-change validation and auditing

REPORT REQUIREMENTS:
- Do NOT return JSON.
- Write normal prose with clear section headings.
- Target audience: senior SRE / platform engineer.
- Be precise, avoid marketing language.

RECOMMENDED SECTIONS:
1. Executive Summary
   - 2–4 sentences summarizing OSV vulnerability, impact level, and key actions
2. Vulnerability Details
   - OSV ID, aliases, severity
   - High-level description of what is being patched (no CVSS boilerplate)
3. Impact Assessment
   - Impact level and why (reference execution domain, reboot, services, fanout)
   - Whether this is kernel/boot-time vs userspace
4. Service & Reboot Plan
   - Explicitly state:
     * Whether a reboot is required
     * Whether any services must be restarted and which ones
     * What happens if the reboot or restart is deferred
5. Blast Radius & Dependency Considerations
   - Reverse dependency / fanout summary
   - Core system involvement (kernel, glibc, openssl, systemd, node, python, npm, pip, etc.)
6. Operational Plan
   - Recommended maintenance window characteristics (e.g., can be done in business hours vs off-hours)
   - High-level rollout / sequencing notes (single node vs fleet, staggered vs big-bang)
7. Validation & Rollback
   - Key checks to perform after applying the update
   - High-level rollback considerations (what would rolling back look like)
8. Appendix: Signals Used
   - Briefly list which signals informed the decision:
     * reboot_required, execution_domain
     * service_requires_restart, restart_services
     * live audit radius summary
     * reverse dependency fanout

STYLE:
- Use short paragraphs and bullet points where helpful.
- Use concrete language (e.g., "Reboot is required on all nodes" instead of "A system restart may be necessary").
- Make the report self-contained: do not assume the reader has seen the raw JSON.
"""

def call_llm(stage_name, model, system_prompt, user_prompt, temperature):
    print(f"\n{'='*80}")
    print(f"[{stage_name}] LLM REQUEST")
    print(f"{'='*80}")
    print(user_prompt)

    response = ollama.chat(
        model=model,
        format="json",
        options={"temperature": temperature},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    )

    raw = response["message"]["content"]

    print(f"\n{'-'*80}")
    print(f"[{stage_name}] LLM RAW RESPONSE")
    print(f"{'-'*80}")
    print(raw)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"[{stage_name}] Invalid JSON from LLM") from e

    return parsed


def stage1_extract_facts(data):
    """Stage 1: Extract and validate key operational facts"""
    
    live_signal = data.get('live_audit_signal', {})
    radius_counts = live_signal.get('radius_counts', {})
    restart_services = data.get('restart_services', [])
    reboot_required_signal = data.get('reboot_required_signal', False)
    
    # Determine execution domain explicitly
    execution_domain = "BOOT_TIME" if reboot_required_signal else "USERSPACE"
    
    prompt = (
        f"### EXECUTION DOMAIN DETERMINATION (MANDATORY MAPPING)\n"
        f"reboot_required_signal = {reboot_required_signal}\n"
        f"\n"
        f"EXECUTION DOMAIN RULE:\n"
        f"  IF reboot_required_signal = TRUE  → execution_domain = \"BOOT_TIME\"\n"
        f"  IF reboot_required_signal = FALSE → execution_domain = \"USERSPACE\"\n"
        f"\n"
        f"Based on reboot_required_signal = {reboot_required_signal}:\n"
        f"  → execution_domain MUST be \"{execution_domain}\"\n"
        f"\n"
        f"⚠️  DO NOT use package names, rationale text, or any other information.\n"
        f"⚠️  ONLY use the reboot_required_signal boolean value.\n"
        f"⚠️  This applies to ALL packages (kernel, npm packages, python packages, etc.).\n"
        f"\n"
        
        f"### RESTART SIGNALS (AUTHORITATIVE)\n"
        f"restart_required_signal = {data.get('restart_required_signal', False)}\n"
        f"restart_services = {json.dumps(restart_services)}\n"
        f"Number of Services Requiring Restart: {len(restart_services)}\n"
        f"\n"
        
        f"### LIVE AUDIT COUNTS\n"
        f"Direct Exec Count: {radius_counts.get('direct_exec', 0)}\n"
        f"Shared Dependency Count: {radius_counts.get('shared_dependency', 0)}\n"
        f"Package Component Count: {radius_counts.get('package_component', 0)}\n"
        f"\n"
        
        f"### EXTRACTION INSTRUCTIONS\n"
        f"Extract the facts exactly as provided:\n"
        f"1. reboot_required = {reboot_required_signal} (copy exactly)\n"
        f"2. service_requires_restart = {data.get('restart_required_signal', False)} (copy exactly)\n"
        f"3. restart_services = {json.dumps(restart_services)} (copy exactly)\n"
        f"4. execution_domain = \"{execution_domain}\" (use the mapping rule above)\n"
        f"5. affected_service_count = {len(restart_services)} (length of restart_services list)\n"
        f"6. direct_exec_count = {radius_counts.get('direct_exec', 0)} (copy exactly)\n"
        f"7. shared_dependency_count = {radius_counts.get('shared_dependency', 0)} (copy exactly)\n"
        f"\n"
        f"Do not modify any values. Do not interpret. Copy exactly as shown."
    )
    
    facts = call_llm(
        stage_name="STAGE 1 — FACT EXTRACTION",
        model="qwen2.5:3b",
        system_prompt=STAGE1_SYSTEM_PROMPT,
        user_prompt=prompt,
        temperature=0.1
    )

    return facts

def stage2_assess_impact(data, facts):
    """Stage 2: Determine impact level based on validated facts"""
    
    # Build critical validation message
    reboot_required = facts['reboot_required']
    service_restart = facts['service_requires_restart']
    
    critical_check = ""
    if reboot_required:
        critical_check = (
            f"\n{'='*70}\n"
            f"🚨 CRITICAL: reboot_required = TRUE\n"
            f"🚨 You MUST output MODERATE-HIGH or HIGH\n"
            f"🚨 Do NOT check service counts - they are IRRELEVANT\n"
            f"🚨 This is a boot-time/kernel update - always high impact\n"
            f"🚨 If you output LOW, LOW-MODERATE, or MODERATE, you are WRONG\n"
            f"{'='*70}\n"
        )
    elif service_restart:
        critical_check = (
            f"\n⚠️  EXCLUSION: service_requires_restart is TRUE, so LOW is IMPOSSIBLE.\n"
            f"⚠️  You MUST choose LOW-MODERATE or higher.\n"
        )
    
    prompt = (
        f"{critical_check}"
        
        f"### STEP 1: CHECK reboot_required (MANDATORY FIRST STEP)\n"
        f"reboot_required = {reboot_required}\n"
        f"execution_domain = {facts['execution_domain']}\n"
        f"\n"
        f"IF reboot_required = TRUE:\n"
        f"  → Your answer MUST be MODERATE-HIGH or HIGH\n"
        f"  → STOP - do not proceed to service checks\n"
        f"  → Choose HIGH if kernel/core system, MODERATE-HIGH otherwise\n"
        f"\n"
        f"IF reboot_required = FALSE:\n"
        f"  → Continue to service checks below\n"
        f"\n"
        
        f"### STEP 2: SERVICE CHECKS (ONLY if reboot_required = FALSE)\n"
        f"Service Requires Restart: {service_restart}\n"
        f"Affected Service Count: {facts['affected_service_count']}\n"
        f"Restart Services: {json.dumps(facts.get('restart_services', []))}\n"
        f"\n"
        f"IF service_requires_restart = FALSE:\n"
        f"  → Impact is LOW\n"
        f"\n"
        f"IF service_requires_restart = TRUE:\n"
        f"  → LOW is IMPOSSIBLE, use service count to determine level\n"
        f"\n"
        
        f"### ADDITIONAL CONTEXT (for reference only)\n"
        f"Execution Domain: {facts['execution_domain']}\n"
        f"Direct Exec Count: {facts['direct_exec_count']}\n"
        f"Shared Dependency Count: {facts['shared_dependency_count']}\n"
        f"Average Reverse Dependencies: {data.get('average_reverse_deps', 0)}\n"
        f"Fanout Level: {data.get('fanout_level', 'LOW')}\n"
        f"Core System Libraries Involved: {data.get('is_core_impact', False)}\n"
        f"Affected Packages: {json.dumps(data.get('affected_packages', []), indent=2)[:500]}\n"
        f"Minimum Impact Level: {data.get('minimum_impact_level') or 'NONE'}\n"
        f"\n"
        
        f"### VALIDATION CHECK\n"
        f"Before outputting your answer, verify:\n"
        f"- If reboot_required = {reboot_required}, did you follow Step 1?\n"
        f"- If reboot_required = TRUE, is your impact MODERATE-HIGH or HIGH?\n"
        f"- If reboot_required = FALSE AND service_requires_restart = {service_restart}, did you follow Step 2?\n"
    )
    
    impact = call_llm(
        stage_name="STAGE 2 — IMPACT ASSESSMENT",
        model="qwen2.5:3b",
        system_prompt=STAGE2_SYSTEM_PROMPT,
        user_prompt=prompt,
        temperature=0.3
    )

    return impact


def stage3_generate_narrative(data, facts, impact):
    """Stage 3: Generate human-readable summary and justification"""
    
    live_signal_str = json.dumps(data.get('live_audit_signal', {}).get('radius', {}), indent=2)
    
    prompt = (
        f"### OSV VULNERABILITY CONTEXT\n"
        f"Vulnerability ID: {data.get('vuln_id', 'Unknown')}\n"
        f"Aliases: {', '.join(data.get('aliases', []))}\n"
        f"Severity: {data.get('severity', 'Unknown')}\n"
        f"Affected Packages: {json.dumps(data.get('affected_packages', {}), indent=2)[:500]}\n\n"
        
        f"### VALIDATED FACTS\n"
        f"{json.dumps(facts, indent=2)}\n\n"
        
        f"### IMPACT ASSESSMENT\n"
        f"Impact Level: {impact['impact_level']}\n"
        f"Reasoning: {impact['reasoning']}\n\n"
        
        f"### DEPENDENCY DATA\n"
        f"Average Reverse Deps: {data.get('average_reverse_deps', 0)}\n"
        f"Fanout Level: {data.get('fanout_level', 'LOW')}\n\n"
        
        f"### LIVE AUDIT DETAILS\n"
        f"{live_signal_str}\n\n"
        
        f"Generate a concise summary and detailed technical justification. "
        f"Reference specific facts, service counts, and execution domain."
    )
    
    narrative = call_llm(
        stage_name="STAGE 3 — NARRATIVE GENERATION",
        model="qwen2.5:3b",
        system_prompt=STAGE3_SYSTEM_PROMPT,
        user_prompt=prompt,
        temperature=0.5
    )

    return narrative


def stage4_generate_report(data, facts, impact, narrative):
    """Stage 4: Generate a full, human-readable SRE report (non-JSON)"""

    live_radius = data.get("live_audit_signal", {}).get("radius", {})
    radius_counts = data.get("live_audit_signal", {}).get("radius_counts", {})

    user_prompt = (
        f"### OSV VULNERABILITY METADATA\n"
        f"ID: {data.get('vuln_id', 'Unknown')}\n"
        f"Aliases: {', '.join(data.get('aliases', []))}\n"
        f"Severity: {data.get('severity', 'Unknown')}\n"
        f"Affected Packages: {json.dumps(data.get('affected_packages', {}), indent=2)}\n\n"

        f"### VALIDATED FACTS (FROM STAGE 1)\n"
        f"{json.dumps(facts, indent=2)}\n\n"

        f"### IMPACT ASSESSMENT (FROM STAGE 2)\n"
        f"{json.dumps(impact, indent=2)}\n\n"

        f"### SHORT NARRATIVE (FROM STAGE 3)\n"
        f"{json.dumps(narrative, indent=2)}\n\n"

        f"### LIVE AUDIT SIGNAL (RADIUS)\n"
        f"Radius counts: {json.dumps(radius_counts, indent=2)}\n"
        f"Radius detail: {json.dumps(live_radius, indent=2)}\n\n"

        f"Using all of the structured data above, write the final SRE report.\n"
        f"Remember: the output must be a human-readable report, not JSON.\n"
    )

    # For the report, we want free-form text, not JSON, so we bypass call_llm
    response = ollama.chat(
        model="qwen2.5:3b",
        options={"temperature": 0.5},
        messages=[
            {"role": "system", "content": STAGE4_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )

    report_text = response["message"]["content"]

    print(f"\n{'='*80}")
    print("[STAGE 4 — FINAL SRE REPORT]")
    print(f"{'='*80}")
    print(report_text)

    return report_text


def llm_assess(data):
    """Multi-stage LLM assessment pipeline"""
    
    print("  [Stage 1/4] Extracting and validating facts...")
    facts = stage1_extract_facts(data)
    print("\n[Stage 1 OUTPUT]")
    print(json.dumps(facts, indent=2))
    
    print("  [Stage 2/4] Assessing impact level...")
    impact = stage2_assess_impact(data, facts)
    
    print("\n[Stage 2 OUTPUT]")
    print(json.dumps(impact, indent=2))
    
    print("  [Stage 3/4] Generating narrative...")
    narrative = stage3_generate_narrative(data, facts, impact)

    print("\n[Stage 3 OUTPUT]")
    print(json.dumps(narrative, indent=2))

    print("  [Stage 4/4] Generating full SRE report...")
    report = stage4_generate_report(data, facts, impact, narrative)
    
    # Combine all results
    return {
        "impact_level": impact["impact_level"],
        "summary": narrative["summary"],
        "technical_justification": narrative["technical_justification"],
        "reboot_required": facts["reboot_required"],
        "service_requires_restart": facts["service_requires_restart"],
        "restart_services": facts["restart_services"],
        "sre_report": report,
    }
