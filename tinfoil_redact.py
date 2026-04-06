#!/usr/bin/env python3
"""Send a sample document to Tinfoil and ask it to redact sensitive information."""

import os
from tinfoil import TinfoilAI

SAMPLE_DOCUMENT = """
INTERNAL MEMO — Q1 Performance Review

To: Sarah Johnson (sarah.johnson@acme-corp.com)
From: David Chen, VP Engineering
Date: March 15, 2026
SSN on file: 478-39-2851

RE: Compensation Adjustment for Employee #A-20441

Sarah's annual salary will increase from $185,000 to $210,000 effective April 1, 2026.
Her corporate Amex ending in 4829 should be updated to reflect the new cost center (CC-7712).

Home address: 1847 Maple Drive, Apt 3B, San Jose, CA 95126
Emergency contact: Michael Johnson, (408) 555-0173

AWS account credentials for the staging environment:
  Access Key: AKIAIOSFODNN7EXAMPLE
  Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

Please also update the DNS record for api.acme-corp.com (IP: 10.0.47.12) and rotate
the database password (currently: Tr0ub4dor&3) before the next audit cycle.
"""

SYSTEM_PROMPT = """\
You are a document redaction assistant. Given a document, replace every piece of \
sensitive or personally identifiable information with a descriptive placeholder in \
square brackets. Redact: names, emails, SSNs, salaries, dollar amounts, credit card \
numbers, addresses, phone numbers, employee IDs, cost centers, credentials, keys, \
passwords, and internal IPs. Preserve all other text and formatting exactly."""


def main() -> None:
    client = TinfoilAI(api_key=os.environ["TINFOIL_API_KEY"])

    response = client.chat.completions.create(
        model="llama3-3-70b",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": SAMPLE_DOCUMENT},
        ],
        temperature=0.0,
    )

    print("=== REDACTED DOCUMENT ===\n")
    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
