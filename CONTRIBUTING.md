# Contributing to RCEPayloadGen

Thanks for your interest in improving RCEPayloadGen! This document explains how
to contribute effectively and the standards the project holds itself to.

## Scope & ethics

RCEPayloadGen is an **RCE testing toolkit for authorised security testing**.
Contributions are welcome, but by opening a pull request you agree that your
change is intended for lawful, authorised use only (penetration testing,
security research, education, and defensive tooling).

Please **do not** submit:

- payloads or features designed for mass targeting, worming/self-propagation,
  or destruction of data as an end in itself;
- anything that weakens the built-in safety controls (consent gate, safety
  tiers, audit logging, the destructive-payload guard) without a clear,
  authorised-testing rationale.

## What we're looking for

- New payload **categories**, **sinks**, or **environments**
- Additional **contexts** (with correct escaping) or **encodings** (that stay
  executable — see below)
- Bug fixes and correctness improvements
- Better **oracles** / success signatures for auto-verification
- Documentation and test improvements

## Development setup

```bash
git clone https://github.com/kabiri-labs/rcpayloadgen.git
cd rcpayloadgen        # Python 3.8+, standard library only — no dependencies
python -m unittest discover -s tests
