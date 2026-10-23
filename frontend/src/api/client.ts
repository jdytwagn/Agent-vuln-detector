const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type ScanTask = {
  id: string;
  source_path: string;
  status: "pending" | "running" | "completed" | "completed_with_errors" | "failed";
  model_backend: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  error?: string;
  summary_json?: Record<string, unknown>;
  report_json_path?: string;
  report_md_path?: string;
};

export type Finding = {
  candidate_id: string;
  file_path: string;
  line: number;
  function_name: string;
  code: string;
  sink: string;
  rule_evidence: {
    cwe: string;
    owasp?: string;
    name: string;
    severity: string;
    description: string;
    recommendation: string;
    tags?: string[];
  };
  model_score?: { score: number; label: string; confidence: number; model_name: string };
  dataflow?: { reachable: boolean; source?: string; sink?: string; scope: string; steps: string[]; sanitized?: boolean; sanitizer?: string };
  semantic_explanation: string;
  exploitability: string;
  exploitability_reason: string;
  final_confidence: number;
  final_severity: string;
  final_decision: string;
};

export type Rule = {
  rule_id: string;
  cwe: string;
  owasp: string;
  name: string;
  severity: string;
  sink_pattern: string;
  tags: string[];
  description: string;
  recommendation: string;
};

export type EvaluationTask = {
  id: string;
  manifest_path: string;
  status: "pending" | "running" | "completed" | "completed_with_errors" | "failed";
  model_backend: string;
  metrics_json?: {
    proposed_agent?: Record<string, number | string>;
    document_baselines?: Array<Record<string, number | string>>;
    runs?: Record<string, Record<string, unknown>>;
    skipped?: Record<string, string>;
    failed?: Record<string, string>;
  };
  error?: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

export const api = {
  listScans: () => request<ScanTask[]>("/api/scans"),
  createScan: (source_path: string, model_backend = "mock", model_path = "", enable_llm_semantics = false, strict_model = false) =>
    request<ScanTask>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ source_path, model_backend, model_path: model_path || null, enable_llm_semantics, strict_model })
    }),
  uploadScan: async (file: File, model_backend = "mock", model_path = "", enable_llm_semantics = false, strict_model = false) => {
    const form = new FormData();
    form.append("file", file);
    form.append("model_backend", model_backend);
    if (model_path) form.append("model_path", model_path);
    form.append("enable_llm_semantics", String(enable_llm_semantics));
    form.append("strict_model", String(strict_model));
    const response = await fetch(`${API_BASE}/api/scans/upload`, { method: "POST", body: form });
    if (!response.ok) throw new Error(await response.text());
    return response.json() as Promise<ScanTask>;
  },
  findings: (id: string) => request<Finding[]>(`/api/scans/${id}/findings`),
  rules: () => request<Rule[]>("/api/rules"),
  listEvaluations: () => request<EvaluationTask[]>("/api/evaluations"),
  createEvaluation: (
    manifest_path: string,
    model_backend = "mock",
    model_path = "",
    enable_llm_semantics = false,
    strict_model = false,
    run_baseline_suite = false,
    skip_code_models = false,
    gnn_epochs = 20,
    codebert_model_path = "storage/models/codebert-devign-code-vulnerability-detector-git",
    graphcodebert_model_path = "storage/models/graphcodebert-devign-code-vulnerability-detector-git"
  ) =>
    request<EvaluationTask>("/api/evaluations", {
      method: "POST",
      body: JSON.stringify({
        manifest_path,
        model_backend,
        model_path: model_path || null,
        enable_llm_semantics,
        strict_model,
        run_baseline_suite,
        skip_code_models,
        gnn_epochs,
        codebert_model_path,
        graphcodebert_model_path
      })
    })
  ,
  downloadReport: async (id: string, format: "json" | "md") => {
    const response = await fetch(`${API_BASE}/api/scans/${id}/report?format=${format}`);
    if (!response.ok) throw new Error(await response.text());
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = format === "md" ? `${id}.md` : `${id}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  }
};
