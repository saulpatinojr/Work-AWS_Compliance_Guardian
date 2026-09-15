# EARS Requirements
- WHEN EventBridge fires, THE SYSTEM SHALL collect Security-pillar signals without modifying audited resources.
- WHEN drift is detected, THE SYSTEM SHALL persist a versioned normalized finding with evidence and correlation ID.
- WHEN no remediation permit matches, THE SYSTEM SHALL deny the call at the Gateway boundary and record the decision.
- WHEN any forbid matches, THE SYSTEM SHALL deny regardless of permits.
- WHEN remediation mode changes, THE SYSTEM SHALL change only the active permit policy-set version and audit the operation.
- WHEN a permitted remediation repeats, THE SYSTEM SHALL be idempotent.
- WHEN a target is untagged or production-tagged, THE SYSTEM SHALL deny mutation.
- WHEN the POC admin opens the console, THE SYSTEM SHALL display findings, effective policies, remediation mode, and decision evidence.
- WHEN voice is started, THE SYSTEM SHALL provide read-only findings summaries and support interruption.
