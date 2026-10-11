# ConsentCompass

ConsentCompass is a GenLayer Intelligent Contract that turns a proposed data use into an auditable, source-bound consent decision.

## What it does

A requester records a purpose, data categories, and three HTTPS sources: a privacy policy, a notice, and regulator guidance. Validators independently fetch each source and classify the use as `ALLOWED`, `RESTRICTED`, `BLOCKED`, or `UNCLEAR`. The contract stores the decision, conditions, confidence, and SHA-256 digests of the exact evidence used.

## Contract flow

1. `create_request(request_id, policy_url, notice_url, regulator_url, purpose, data_categories)` opens a pending request.
2. `evaluate(request_id)` runs independent consensus and finalizes the decision.
3. `get_request(owner, request_id)` returns the attributable receipt.

The contract requires three distinct HTTPS hosts, rejects duplicate IDs, treats conflicting evidence as an explicit outcome, and blocks replay after finalization.

## Tests

```text
pytest -q test_consent_compass.py
```

The suite covers final classification, distinct-host validation, and rejection of forged validator output.
