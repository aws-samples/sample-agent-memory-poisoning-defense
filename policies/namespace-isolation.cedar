// Cedar Policies: Namespace Isolation for AgentCore Memory
//
// These policies enforce trust boundaries between memory namespaces.
// They complement the Validation Lambda by providing deterministic
// access control at the AgentCore Policy layer.

// =============================================================
// POLICY 1: Agents can write to their assigned user namespace
// =============================================================
permit(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryWrite",
  resource
)
when {
  resource.namespace.startsWith("user/") &&
  resource.namespace.startsWith("user/" + context.session.userId + "/")
};

// =============================================================
// POLICY 2: Block ALL runtime writes to system namespace
// =============================================================
forbid(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryWrite",
  resource
)
when {
  resource.namespace.startsWith("system/")
};

// =============================================================
// POLICY 3: Shared namespace requires elevated permission
// =============================================================
permit(
  principal in AgentGroup::"elevated-agents",
  action == Action::"MemoryWrite",
  resource
)
when {
  resource.namespace.startsWith("shared/") &&
  context.validation.compositeScore < 40
};

// =============================================================
// POLICY 4: Only the Validation Lambda can write to quarantine
// =============================================================
permit(
  principal == Service::"memory-validator-lambda",
  action == Action::"MemoryWrite",
  resource
)
when {
  resource.namespace.startsWith("quarantine/")
};

// =============================================================
// POLICY 5: Block agents from reading quarantine namespace
// =============================================================
forbid(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryRead",
  resource
)
when {
  resource.namespace.startsWith("quarantine/")
};

// =============================================================
// POLICY 6: Agents cannot write to another user's namespace
// =============================================================
forbid(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryWrite",
  resource
)
when {
  resource.namespace.startsWith("user/") &&
  !resource.namespace.startsWith("user/" + context.session.userId + "/")
};

// =============================================================
// POLICY 7: Read access to shared namespace (all agents)
// =============================================================
permit(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryRead",
  resource
)
when {
  resource.namespace.startsWith("shared/")
};

// =============================================================
// POLICY 8: Agents can read system namespace (for config)
// =============================================================
permit(
  principal in AgentGroup::"runtime-agents",
  action == Action::"MemoryRead",
  resource
)
when {
  resource.namespace.startsWith("system/")
};
