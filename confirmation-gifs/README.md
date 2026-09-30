# Confirmation demos

Screen recordings backing the "Confirmations" section of the main
[`README`](../README.md). Each shows RCEKit reaching an **`executed`** (or, for
blind timing, a **`timing-sink`**) verdict against a real, publicly-documented
vulnerability — the verdict differenced against a payload-free control.

**These four were recorded before 3.0.0 and print the old verdict names.** On
screen you will see `confirmed` where the tool now prints `executed`, and
`needs-review` where `time` now prints `timing-sink`. Only the words changed:
3.0.0 renamed the tiers after what the target did, and moved three settled
measurements out from under `needs-review`. What each run proves, and the
evidence line it proves it with, is the same. They will be re-recorded the next
time these labs are brought up.

| File | Method | Target |
|---|---|---|
| `reflected-webmin-cve-2019-15107.gif` | `reflected` (OS command injection) | Webmin 1.910 — CVE-2019-15107 |
| `eval-struts2-s2-001.gif` | `eval` (OGNL expression injection) | Apache Struts2 — S2-001 |
| `time-webmin-cve-2019-15107.gif` | `time` (blind timing) | Webmin 1.910 — CVE-2019-15107 |
| `oob-log4shell-cve-2021-44228.gif` | out-of-band DNS callback | Log4Shell — CVE-2021-44228 |

All targets were run locally in disposable Docker labs (vulhub) for authorised testing only.
