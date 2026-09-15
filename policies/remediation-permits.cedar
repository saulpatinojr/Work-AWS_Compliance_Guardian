// Inactive by default; control-plane activation must be versioned and audited.
permit(principal, action, resource) when { resource.hasTag("CCGDemo", "true") && !resource.hasTag("Environment", "prod") };
