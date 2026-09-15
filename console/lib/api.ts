export type PolicyState = {
  policy_engine_id: string;
  policy_set_version: string;
  enforcement_mode: "LOG_ONLY" | "ACTIVE";
  generation: number;
  updated_by: string;
  updated_at: string;
};

export type Finding = {
  finding_id: string;
  rule_id: string;
  severity: string;
  title: string;
  target_arn: string;
  status: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function getPolicyState(): Promise<PolicyState> {
  return apiFetch<PolicyState>("/policy");
}

export async function getFindings(): Promise<Finding[]> {
  const response = await apiFetch<{ findings: Finding[] }>("/findings");
  return response.findings;
}

export function requestPolicyActivation(input: {
  requestedVersion: string;
  expectedGeneration: number;
  reason: string;
  activate: boolean;
}): Promise<unknown> {
  return apiFetch("/policy/activation", {
    method: "POST",
    body: JSON.stringify(input),
  });
}
