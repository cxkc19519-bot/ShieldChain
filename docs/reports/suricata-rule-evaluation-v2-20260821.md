# ShieldChain Suricata Custom Rule Evaluation v2

Date: 2026-08-21

## Scope

- Dataset: anonymized NTA PCAP corpus
- Development split: used for rule authoring
- Validation split: frozen before label reveal
- Final blind split: 935 samples, untouched
- Classification input: Suricata alerts and Zeek protocol metadata only
- Filename labels: not used by the detector
- Ruleset SHA-256: bccf8871de64d28cda338f96222365e83411b79abd971c8386e05a04c4016aee

## v2 rules added

Protocol-behaviour signatures were added for:

- WebLogic WSAT and console JNDI exploitation
- Elasticsearch scripted search requests
- MSSQL command execution primitives
- Oracle UNION and time-based extraction patterns
- Struts runtime command execution
- JBoss readonly invoker deserialization
- Upload of server-side script files

All custom rules are alert-only. They do not block traffic or trigger automatic response.

## Development regression

Run: run-20260821-133041

The targeted 20-sample development regression showed expected v2 hits for WebLogic,
Elasticsearch, HTTP-delivered MSSQL command execution, Oracle injection, Struts/JBoss
exploitation, and server-side script upload. Existing WebShell and large-POST rules
continued to work.

Two targeted checks after the regression:

- run-20260821-133942: WebLogic console JNDI expression matched SID 9000024.
- run-20260821-133942: Oracle time-based blind extraction matched SID 9000023.

## Independent validation

Run: run-20260821-134145
Sample list: validation-sample-v2-24.txt

- Samples: 24
- Samples with effective Suricata security alerts: 8/24 (33.3%)
- Samples with ShieldChain custom-rule hits: 8/24 (33.3%)
- Pending-review classifications: 15/24 (62.5%)
- Detector classifications: 3 suspected Web exploitation, 3 suspected WebShell
  interaction, 3 exploitation, 15 pending review
- Decoder/checksum events were excluded from security-alert counts.

The earlier v1 frozen validation used a different 24-sample set and produced:

- Effective Suricata hit coverage: 4/24 (16.7%)
- ShieldChain custom-rule hit coverage: 2/24 (8.3%)

These are different random slices, so the comparison is directional rather than a
controlled paired accuracy measurement.

## Post-freeze label audit

Only after the v2 run was complete were the 24 validation mappings inspected.

Nine validation files had human-readable attack descriptions. Six were detected or
meaningfully classified:

- Godzilla JSP WebShell traffic
- JBoss CVE-2017-12149 exploitation
- HTTP tunnel/covert communication
- Struts S2-053 WebShell-write activity
- CVE-2015-8103 JSP WebShell upload
- MSSQL sp_addextendedproc activity

Three descriptive samples remained pending review:

- Response command / Windows findstr
- JFoler WebShell
- AntSword PHP XOR/cookie variant

## Limitations

This validation set does not include a verified benign corpus. Therefore precision,
false-positive rate, specificity, and production accuracy cannot be calculated.
The 33.3% figure is detection coverage on this validation slice, not model accuracy.

Direct MSSQL TDS payloads can be fragmented, encoded, or unavailable to simple
content rules. Encrypted traffic and unknown application protocols require endpoint
telemetry, TLS visibility, or higher-level correlation.

## Next recommended work

1. Add a benign enterprise-traffic corpus and measure false positives.
2. Add Zeek behavioural detections for HTTP tunnel periodicity and long-lived sessions.
3. Add endpoint/Wazuh correlation for command execution and WebShell file creation.
4. Develop signatures for the three missed descriptive families using development-only
   examples.
5. Keep the 935-sample final blind split sealed until the rules and evaluation protocol
   are fully frozen.
