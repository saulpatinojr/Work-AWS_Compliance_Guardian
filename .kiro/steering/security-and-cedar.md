# Cedar-first authorization
Dangerous actions must traverse a Gateway/policy boundary. Never authorize via prompt, memory, UI state, or application boolean. Forbid overrides permit and default deny must be tested. Deny mutations unless `CCGDemo=true`; always deny `Environment=prod`.
