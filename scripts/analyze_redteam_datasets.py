#!/usr/bin/env python3
"""Analyze red team datasets against CloneGuard CaMeL-lite SEQ rules.

SAFETY: This script only PARSES data as strings. No eval, no exec, no
shell execution of any payload content. All adversarial data stays in
data/redteam/ (gitignored).

Datasets analyzed:
- InjecAgent: test cases (17 user tools x 62 attacker tools)
- AgentDojo: Injection task definitions from source code

Output: data/redteam/combined_analysis.json + stdout summary
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Attacker tools implying exfiltration via network (SEQ-001/002 pattern)
EXFIL_TOOLS = {
    "GmailSendEmail", "SlackSendMessage", "TelegramSendMessage",
    "DiscordSendMessage", "WhatsAppSendMessage", "TwitterPostTweet",
    "FacebookPostMessage", "SendGrid", "TwilioSendSMS",
    "send_email", "post_webpage", "send_message",
}

CONFIG_TOOLS = {
    "AWSSetSecurityGroup", "GoogleCloudSetFirewall",
    "AugustSmartLock", "NestSetTemperature", "PhilipsHueLightControl",
}

FINANCIAL_TOOLS = {
    "BinancePlaceOrder", "RobinhoodPlaceOrder", "PayPalSendPayment",
    "VenmoSendPayment", "StripeCreateCharge",
    "send_money", "schedule_transaction", "update_scheduled_transaction",
}


def classify_injecagent_case(case: dict) -> dict:
    attacker_tools_raw = case.get("Attacker Tools", "[]")
    try:
        attacker_tools = json.loads(attacker_tools_raw.replace("'", '"'))
    except (json.JSONDecodeError, AttributeError):
        attacker_tools = re.findall(r"'(\w+)'", str(attacker_tools_raw))

    attack_type = case.get("Attack Type", "unknown")
    instruction = case.get("Attacker Instruction", "")
    seq_rules = []
    gap_reason = None

    has_exfil = any(t in EXFIL_TOOLS for t in attacker_tools)
    has_config = any(t in CONFIG_TOOLS for t in attacker_tools)
    has_financial = any(t in FINANCIAL_TOOLS for t in attacker_tools)

    if has_exfil:
        seq_rules.append("GAP:MCP-exfil")
        gap_reason = "Exfil via tool-specific send, not WebFetch/curl"
    elif has_config:
        seq_rules.append("SEQ-005")
    elif has_financial:
        seq_rules.append("GAP:financial")
        gap_reason = "Financial manipulation via tool call"
    else:
        seq_rules.append("GAP:other")
        gap_reason = f"Attacker tools {attacker_tools} unmapped"

    return {
        "attacker_tools": attacker_tools,
        "attack_type": attack_type,
        "instruction_preview": instruction[:150],
        "seq_rules": seq_rules,
        "gap_reason": gap_reason,
    }


def analyze_injecagent(data_dir: Path) -> dict:
    results = {"data_stealing": [], "direct_harm": []}
    for fname, cat in [
        ("attacker_cases_ds.jsonl", "data_stealing"),
        ("attacker_cases_dh.jsonl", "direct_harm"),
    ]:
        fpath = data_dir / fname
        if not fpath.exists():
            print(f"  WARNING: {fpath} not found")
            continue
        with open(fpath, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                case = json.loads(line)
                classified = classify_injecagent_case(case)
                classified["source_file"] = fname
                results[cat].append(classified)
    return results


def analyze_agentdojo_source(venv_path: Path) -> list[dict]:
    results = []
    injection_files = list(venv_path.glob(
        "lib/python*/site-packages/agentdojo/default_suites/v1/*/injection_tasks.py"
    ))
    for fpath in injection_files:
        suite = fpath.parent.name
        content = fpath.read_text(encoding="utf-8")
        goals = re.findall(
            r'GOAL\s*=\s*(?:f?"""(.*?)"""|f?"(.*?)"|f?\((.*?)\))',
            content, re.DOTALL,
        )
        classes = re.findall(r'class\s+(\w+)', content)
        for i, (g1, g2, g3) in enumerate(goals):
            goal = (g1 or g2 or g3).strip()
            class_name = classes[i] if i < len(classes) else f"unknown_{i}"
            seq_rules = []
            gl = goal.lower()
            if any(w in gl for w in ["email", "send", "post", "website"]):
                if any(w in gl for w in ["concatenate", "body", "code", "password", "iban"]):
                    seq_rules.append("GAP:MCP-exfil")
                else:
                    seq_rules.append("GAP:social-engineering")
            elif any(w in gl for w in ["delete", "remove"]):
                seq_rules.append("GAP:destructive")
            elif any(w in gl for w in ["transfer", "send money", "transaction"]):
                seq_rules.append("GAP:financial")
            elif any(w in gl for w in ["visit", "link", "phishing"]):
                seq_rules.append("SEQ-001")
            elif any(w in gl for w in ["reservation", "calendar", "create"]):
                seq_rules.append("GAP:resource-abuse")
            else:
                seq_rules.append("GAP:unclassified")
            results.append({
                "suite": suite, "class": class_name,
                "goal": goal[:200], "seq_rules": seq_rules,
            })
    return results


def main():
    project_root = Path(__file__).parent.parent
    data_dir = project_root / "data" / "redteam" / "injecagent"
    venv_path = project_root / ".venv"

    print("=" * 70)
    print("CloneGuard CaMeL-lite — Red Team Dataset Analysis")
    print("=" * 70)

    # InjecAgent
    print("\n### InjecAgent Analysis ###\n")
    inj = analyze_injecagent(data_dir)
    all_cases = inj["data_stealing"] + inj["direct_harm"]
    total = len(all_cases)
    print(f"Total cases: {total}")
    print(f"  Data stealing: {len(inj['data_stealing'])}")
    print(f"  Direct harm: {len(inj['direct_harm'])}")

    rule_counts: dict[str, int] = {}
    for c in all_cases:
        for r in c["seq_rules"]:
            rule_counts[r] = rule_counts.get(r, 0) + 1

    print("\nSEQ rule mapping:")
    for r, cnt in sorted(rule_counts.items()):
        pct = cnt / total * 100 if total else 0
        print(f"  {r}: {cnt} ({pct:.1f}%)")

    # AgentDojo
    print("\n### AgentDojo Injection Tasks ###\n")
    dojo = analyze_agentdojo_source(venv_path)
    print(f"Total injection tasks extracted: {len(dojo)}")

    dojo_counts: dict[str, int] = {}
    for t in dojo:
        for r in t["seq_rules"]:
            dojo_counts[r] = dojo_counts.get(r, 0) + 1

    print("\nSEQ rule mapping:")
    for r, cnt in sorted(dojo_counts.items()):
        pct = cnt / len(dojo) * 100 if dojo else 0
        print(f"  {r}: {cnt} ({pct:.1f}%)")

    # Combined
    print("\n" + "=" * 70)
    print("COMBINED SUMMARY")
    print("=" * 70)

    total_all = total + len(dojo)
    combined: dict[str, int] = {}
    for r, c in rule_counts.items():
        combined[r] = combined.get(r, 0) + c
    for r, c in dojo_counts.items():
        combined[r] = combined.get(r, 0) + c

    covered = sum(c for r, c in combined.items() if not r.startswith("GAP"))
    gaps = sum(c for r, c in combined.items() if r.startswith("GAP"))

    print(f"\nTotal attack cases: {total_all}")
    print(f"  Covered by SEQ rules: {covered} ({covered / total_all * 100:.1f}%)")
    print(f"  In coverage gaps: {gaps} ({gaps / total_all * 100:.1f}%)")
    print("\nGap breakdown:")
    for r, cnt in sorted(combined.items()):
        if r.startswith("GAP"):
            print(f"  {r}: {cnt}")

    mcp_gap = combined.get("GAP:MCP-exfil", 0)
    print(f"\nKey finding: {mcp_gap} cases use MCP-tool-only exfiltration "
          "(email, messaging, API calls) that bypasses SEQ-001/002.")

    # Save
    output = {
        "injecagent": {
            "total": total,
            "data_stealing": len(inj["data_stealing"]),
            "direct_harm": len(inj["direct_harm"]),
            "rule_mapping": rule_counts,
        },
        "agentdojo": {
            "total": len(dojo),
            "rule_mapping": dojo_counts,
            "tasks": dojo,
        },
        "combined": {
            "total": total_all,
            "covered": covered,
            "gaps": gaps,
            "rule_breakdown": combined,
        },
    }
    out_path = project_root / "data" / "redteam" / "combined_analysis.json"
    out_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"\nFull results saved to {out_path}")


if __name__ == "__main__":
    main()
