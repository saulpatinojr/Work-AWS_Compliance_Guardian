// Validate entity and context names against the live AgentCore Gateway schema.
forbid(principal, action, resource) when { resource.hasTag("Environment", "prod") };
forbid(principal, action == Action::"ModifySecurityGroup", resource) when { resource.proposedCidr == "0.0.0.0/0" };
forbid(principal, action == Action::"ModifySecurityGroup", resource) when { resource.proposedCidr == "::/0" };
forbid(principal, action == Action::"MakeS3Public", resource);
forbid(principal, action == Action::"DisableCloudTrail", resource);
