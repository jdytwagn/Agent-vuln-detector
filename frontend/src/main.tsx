import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, FileCode2, FlaskConical, ListChecks, PlayCircle, RefreshCw, ShieldAlert, Upload } from "lucide-react";
import { api, EvaluationTask, Finding, Rule, ScanTask } from "./api/client";
import { MetricCard } from "./components/MetricCard";
import { StatusPill } from "./components/StatusPill";
import "./styles/app.css";

type Tab = "dashboard" | "scan" | "findings" | "rules" | "evaluation";

const MODEL_PATH_DEFAULTS: Record<string, string> = {
  codebert: "storage/models/codebert-devign-code-vulnerability-detector-git",
  graphcodebert: "storage/models/graphcodebert-devign-code-vulnerability-detector-git"
};
const DEMO_SOURCE_PATH = "tests/samples";

function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [scans, setScans] = useState<ScanTask[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [evaluations, setEvaluations] = useState<EvaluationTask[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const selectedScanIdRef = useRef<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sourcePath, setSourcePath] = useState("tests/samples");
  const [manifestPath, setManifestPath] = useState("evaluation/sample_manifest.json");
  const [modelBackend, setModelBackend] = useState("mock");
  const [modelPath, setModelPath] = useState("");
  const [strictModel, setStrictModel] = useState(false);
  const [enableLlm, setEnableLlm] = useState(false);
  const [runBaselineSuite, setRunBaselineSuite] = useState(false);
  const [skipCodeModels, setSkipCodeModels] = useState(false);
  const [gnnEpochs, setGnnEpochs] = useState(20);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const selectScan = useCallback((id: string) => {
    selectedScanIdRef.current = id;
    setSelectedScanId(id);
  }, []);

  const refresh = useCallback(async (preferredScanId?: string) => {
    const [scanData, ruleData, evaluationData] = await Promise.all([api.listScans(), api.rules(), api.listEvaluations()]);
    setScans(scanData);
    setRules(ruleData);
    setEvaluations(evaluationData);
    const requestedScan = preferredScanId || selectedScanIdRef.current;
    const activeScan = scanData.some((scan) => scan.id === requestedScan) ? requestedScan : scanData[0]?.id || "";
    selectedScanIdRef.current = activeScan;
    setSelectedScanId(activeScan);
    if (activeScan) {
      setFindings(await api.findings(activeScan));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        await refresh();
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : "刷新失败");
      }
      if (!cancelled) timer = window.setTimeout(poll, 3000);
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [refresh]);

  useEffect(() => {
    if (selectedScanId) {
      api.findings(selectedScanId).then(setFindings).catch(() => setFindings([]));
    }
  }, [selectedScanId]);

  const dashboard = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed" || scan.status === "completed_with_errors").length;
    const failed = scans.filter((scan) => scan.status === "failed").length;
    const totals = scans.reduce(
      (sum, scan) => {
        const counts = splitCounts(scan);
        sum.confirmed += counts.confirmed;
        sum.review += counts.review;
        sum.filtered += counts.filtered;
        return sum;
      },
      { confirmed: 0, review: 0, filtered: 0 }
    );
    return { completed, failed, ...totals };
  }, [scans]);

  const selectedScan = scans.find((scan) => scan.id === selectedScanId);
  const effectiveModelPath = modelPath.trim() || MODEL_PATH_DEFAULTS[modelBackend] || "";

  const submitScan = async () => {
    await startScan(sourcePath, `已提交扫描任务`);
  };

  const submitDemoScan = async () => {
    setSourcePath(DEMO_SOURCE_PATH);
    await startScan(DEMO_SOURCE_PATH, "已提交内置样例扫描");
  };

  const startScan = async (targetPath: string, successMessage: string) => {
    setBusy(true);
    try {
      const task = await api.createScan(targetPath, modelBackend, effectiveModelPath, enableLlm, strictModel);
      selectScan(task.id);
      setTab("findings");
      setMessage(`${successMessage}：${task.id}`);
      await refresh(task.id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "提交失败");
    } finally {
      setBusy(false);
    }
  };

  const uploadScan = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    try {
      const task = await api.uploadScan(file, modelBackend, effectiveModelPath, enableLlm, strictModel);
      selectScan(task.id);
      setTab("findings");
      setMessage(`已上传并提交扫描：${file.name}`);
      await refresh(task.id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "上传失败");
    } finally {
      setBusy(false);
      event.target.value = "";
    }
  };

  const submitEvaluation = async () => {
    setBusy(true);
    try {
      const task = await api.createEvaluation(
        manifestPath,
        modelBackend,
        effectiveModelPath,
        enableLlm,
        strictModel,
        runBaselineSuite,
        skipCodeModels,
        gnnEpochs
      );
      setMessage(`已提交评测任务：${task.id}`);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "评测失败");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={28} />
          <div>
            <strong>漏洞检测平台</strong>
            <span>Agent-based SAST</span>
          </div>
        </div>
        <button className={tab === "dashboard" ? "active" : ""} onClick={() => setTab("dashboard")}><Activity size={18} />仪表盘</button>
        <button className={tab === "scan" ? "active" : ""} onClick={() => setTab("scan")}><Upload size={18} />扫描</button>
        <button className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}><ListChecks size={18} />漏洞详情</button>
        <button className={tab === "rules" ? "active" : ""} onClick={() => setTab("rules")}><FileCode2 size={18} />规则库</button>
        <button className={tab === "evaluation" ? "active" : ""} onClick={() => setTab("evaluation")}><FlaskConical size={18} />评测</button>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>{titleFor(tab)}</h1>
            <p>规则、模型、数据流、语义和可利用性共同形成最终判定。</p>
          </div>
          <button className="icon-button" onClick={() => refresh()} title="刷新"><RefreshCw size={18} /></button>
        </header>

        {message && <div className="notice">{message}</div>}

        <div className="tab-panel" key={tab}>
        {tab === "dashboard" && (
          <section className="content-grid">
            <MetricCard label="扫描任务" value={scans.length} />
            <MetricCard label="已完成" value={dashboard.completed} tone="success" />
            <MetricCard label="确认漏洞" value={dashboard.confirmed} tone="danger" />
            <MetricCard label="待复核" value={dashboard.review} tone="warning" />
            <MetricCard label="误报过滤" value={dashboard.filtered} />
            <section className="panel wide">
              <h2>任务概览</h2>
              <TaskTable scans={scans} selectedScanId={selectedScanId} onSelect={selectScan} />
            </section>
            <section className="panel">
              <h2>当前任务严重等级</h2>
              <p className="panel-note">{selectedScan?.source_path || "尚未选择任务"}。只统计该任务里未过滤的结果。</p>
              <SeverityBars findings={findings.filter((item) => item.final_decision !== "filtered_false_positive")} />
            </section>
            <section className="panel span-all">
              <h2>判定链路</h2>
              <ol className="pipeline">
                {["预处理", "规则召回", "数据流", "模型打分", "语义解释", "可利用性", "融合判定"].map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </section>
          </section>
        )}

        {tab === "scan" && (
          <section className="content-grid">
          <section className="panel stack">
            <h2>快速开始</h2>
            <div className="quick-start">
              <button className="demo-button" onClick={submitDemoScan} disabled={busy}>
                <PlayCircle size={18} />扫描内置样例
              </button>
              <span>推荐先跑 `tests/samples`，完成后会自动进入漏洞详情。</span>
            </div>
          </section>
          <section className="panel stack wide">
            <h2>提交扫描</h2>
            <div className="form-row">
              <label>源码路径</label>
              <input value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} />
            </div>
            <div className="form-row">
              <label>模型后端</label>
              <select value={modelBackend} onChange={(event) => setModelBackend(event.target.value)}>
                <option value="mock">mock</option>
                <option value="codebert">CodeBERT</option>
                <option value="graphcodebert">GraphCodeBERT</option>
              </select>
            </div>
            {modelBackend !== "mock" && (
              <div className="form-row">
                <label>模型路径</label>
                <input
                  value={modelPath}
                  onChange={(event) => setModelPath(event.target.value)}
                  placeholder={MODEL_PATH_DEFAULTS[modelBackend]}
                />
              </div>
            )}
            {modelBackend !== "mock" && (
              <label className="check-row">
                <input type="checkbox" checked={strictModel} onChange={(event) => setStrictModel(event.target.checked)} />
                严格模型模式
              </label>
            )}
            <label className="check-row">
              <input type="checkbox" checked={enableLlm} onChange={(event) => setEnableLlm(event.target.checked)} />
              启用 DeepSeek 语义推理
            </label>
            <div className="actions">
              <button onClick={submitScan} disabled={busy}>扫描路径</button>
              <label className="file-button">
                上传压缩包
                <input type="file" accept=".zip,.c,.cc,.cpp,.cxx,.h,.hpp" onChange={uploadScan} />
              </label>
            </div>
          </section>
          </section>
        )}

        {tab === "findings" && (
          <section className="content-grid">
            <section className="panel">
              <h2>扫描任务</h2>
              <TaskTable scans={scans} selectedScanId={selectedScanId} onSelect={selectScan} />
            </section>
            <section className="panel wide">
              <h2>漏洞详情</h2>
              {selectedScanId && (
                <div className="download-row">
                  <button onClick={() => api.downloadReport(selectedScanId, "json").catch((error) => setMessage(error.message))}>JSON 报告</button>
                  <button onClick={() => api.downloadReport(selectedScanId, "md").catch((error) => setMessage(error.message))}>Markdown 报告</button>
                </div>
              )}
              {selectedScan?.error && <p className="error-text">{selectedScan.error}</p>}
              {selectedScan?.summary_json?.model_fallback ? (
                <div className="notice">模型未能加载，本次结果已降级为 mock：{String(selectedScan.summary_json.model_load_error ?? "")}</div>
              ) : null}
              {selectedScan?.summary_json?.parser_fallback ? (
                <div className="notice">Tree-sitter 不可用，预处理已退回轻量解析：{String(selectedScan.summary_json.parser_error ?? "")}</div>
              ) : null}
              <FindingList findings={findings} />
            </section>
          </section>
        )}

        {tab === "rules" && (
          <section className="panel">
            <h2>CWE/OWASP 规则库</h2>
            <div className="rule-grid">
              {rules.map((rule) => (
                <article className="rule-card" key={rule.rule_id}>
                  <div className="rule-head">
                    <strong>{rule.name}</strong>
                    <span>{rule.severity}</span>
                  </div>
                  <p>{rule.cwe} · {rule.owasp}</p>
                  <code>{rule.sink_pattern}</code>
                  <p>{rule.description}</p>
                </article>
              ))}
            </div>
          </section>
        )}

        {tab === "evaluation" && (
          <section className="content-grid">
            <section className="panel stack">
              <h2>提交评测</h2>
              <div className="form-row">
                <label>Manifest</label>
                <input value={manifestPath} onChange={(event) => setManifestPath(event.target.value)} />
              </div>
              <div className="form-row">
                <label>模型后端</label>
                <select value={modelBackend} onChange={(event) => setModelBackend(event.target.value)}>
                  <option value="mock">mock</option>
                  <option value="codebert">CodeBERT</option>
                  <option value="graphcodebert">GraphCodeBERT</option>
                </select>
              </div>
              {modelBackend !== "mock" && (
                <div className="form-row">
                  <label>模型路径</label>
                  <input
                    value={modelPath}
                    onChange={(event) => setModelPath(event.target.value)}
                    placeholder={MODEL_PATH_DEFAULTS[modelBackend]}
                  />
                </div>
              )}
              {modelBackend !== "mock" && (
                <label className="check-row">
                  <input type="checkbox" checked={strictModel} onChange={(event) => setStrictModel(event.target.checked)} />
                  严格模型模式
                </label>
              )}
              <label className="check-row">
                <input type="checkbox" checked={enableLlm} onChange={(event) => setEnableLlm(event.target.checked)} />
                启用 DeepSeek 语义推理
              </label>
              <label className="check-row">
                <input type="checkbox" checked={runBaselineSuite} onChange={(event) => setRunBaselineSuite(event.target.checked)} />
                运行完整基线套件
              </label>
              {runBaselineSuite && (
                <>
                  <label className="check-row">
                    <input type="checkbox" checked={skipCodeModels} onChange={(event) => setSkipCodeModels(event.target.checked)} />
                    跳过 CodeBERT/GraphCodeBERT 纯模型基线
                  </label>
                  <div className="form-row">
                    <label>GNN 训练轮次</label>
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={gnnEpochs}
                      onChange={(event) => setGnnEpochs(Number(event.target.value) || 1)}
                    />
                  </div>
                </>
              )}
              <button onClick={submitEvaluation} disabled={busy}>启动评测</button>
            </section>
            <section className="panel wide">
              <h2>评测指标</h2>
              <EvaluationTable evaluations={evaluations} />
            </section>
          </section>
        )}
        </div>
      </section>
    </main>
  );
}

function splitCounts(scan: ScanTask) {
  const summary = scan.summary_json ?? {};
  if ("confirmed_count" in summary) {
    return {
      confirmed: Number(summary.confirmed_count ?? 0),
      review: Number(summary.review_count ?? 0),
      filtered: Number(summary.filtered_count ?? 0)
    };
  }
  return {
    confirmed: Number(summary.reported_count ?? 0),
    review: 0,
    filtered: Number(summary.filtered_count ?? 0)
  };
}

function formatScanCounts(scan: ScanTask) {
  const counts = splitCounts(scan);
  const parts = [`确认 ${counts.confirmed}`];
  if (counts.review) parts.push(`复核 ${counts.review}`);
  if (counts.filtered) parts.push(`过滤 ${counts.filtered}`);
  return parts.join("，");
}

function decisionLabel(decision: string) {
  return (
    {
      vulnerable: "确认漏洞",
      needs_review: "待复核",
      filtered_false_positive: "误报过滤",
      low_risk: "低风险"
    } as Record<string, string>
  )[decision] ?? decision;
}

function titleFor(tab: Tab) {
  return {
    dashboard: "安全扫描仪表盘",
    scan: "扫描任务",
    findings: "证据链与漏洞详情",
    rules: "规则库",
    evaluation: "实验评测"
  }[tab];
}

function TaskTable({ scans, selectedScanId, onSelect }: { scans: ScanTask[]; selectedScanId: string; onSelect: (id: string) => void }) {
  return (
    <div className="table">
      {scans.map((scan) => (
        <button key={scan.id} className={`table-row ${selectedScanId === scan.id ? "selected" : ""}`} onClick={() => onSelect(scan.id)}>
          <span>{scan.source_path}</span>
          <StatusPill status={scan.status} />
          <span>
            {scan.status === "failed" ? scan.error || "扫描失败" : formatScanCounts(scan)}
          </span>
        </button>
      ))}
      {!scans.length && <p className="empty">暂无扫描任务。</p>}
    </div>
  );
}

function SeverityBars({ findings }: { findings: Finding[] }) {
  const levels = ["critical", "high", "medium", "low"];
  const max = Math.max(1, ...levels.map((level) => findings.filter((item) => item.final_severity === level).length));
  return (
    <div className="bars">
      {levels.map((level) => {
        const count = findings.filter((item) => item.final_severity === level).length;
        return (
          <div className="bar-row" key={level}>
            <span>{level}</span>
            <div><i style={{ width: `${(count / max) * 100}%` }} /></div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <p className="empty">当前任务暂无可展示漏洞。</p>;
  const filteredCount = findings.filter((item) => item.final_decision === "filtered_false_positive").length;
  return (
    <div className="finding-list">
      {filteredCount > 0 && <p className="empty">另有 {filteredCount} 条因缓解逻辑被过滤，仍保留在下方供核对，不计入报告漏洞。</p>}
      {findings.map((item) => (
        <article className={`finding${item.final_decision === "filtered_false_positive" ? " filtered" : ""}`} key={item.candidate_id}>
          <header>
            <div>
              <strong>{item.candidate_id} · {item.rule_evidence.name}</strong>
              <p>{item.file_path}:{item.line} · {item.function_name}</p>
            </div>
            <span className={`severity severity-${item.final_severity}`}>{item.final_severity}</span>
          </header>
          <div className="finding-meta">
            <span>{item.rule_evidence.cwe}</span>
            <span>{item.rule_evidence.owasp}</span>
            <span className={`decision decision-${item.final_decision}`}>{decisionLabel(item.final_decision)}</span>
            <span>置信度 {item.final_confidence}</span>
            {item.model_score ? <span>模型 {item.model_score.score}</span> : null}
          </div>
          <pre>{item.code}</pre>
          <p>{item.semantic_explanation}</p>
          <ol>
            {(item.dataflow?.steps ?? []).map((step) => <li key={step}>{step}</li>)}
          </ol>
          <p className="recommendation">{item.rule_evidence.recommendation}</p>
        </article>
      ))}
    </div>
  );
}

function EvaluationTable({ evaluations }: { evaluations: EvaluationTask[] }) {
  if (!evaluations.length) return <p className="empty">暂无评测任务。</p>;
  return (
    <div className="evaluation-list">
      {evaluations.map((task) => {
        const metrics = task.metrics_json?.proposed_agent;
        const suiteRuns = task.metrics_json?.runs;
        const skipped = task.metrics_json?.skipped ?? {};
        const failed = task.metrics_json?.failed ?? {};
        return (
          <article className="evaluation" key={task.id}>
            <header>
              <strong>{task.manifest_path}</strong>
              <StatusPill status={task.status} />
            </header>
            {suiteRuns ? (
              <div className="suite-runs">
                {Object.entries(suiteRuns).map(([name, run]) => (
                  <MetricLine key={name} name={name} run={run} />
                ))}
                {Object.entries(skipped).map(([name, reason]) => (
                  <p className="empty" key={name}>{name}: {reason}</p>
                ))}
                {Object.entries(failed).map(([name, reason]) => (
                  <p className="error-text" key={name}>{name}: {reason}</p>
                ))}
              </div>
            ) : metrics ? (
              <div className="metric-line">
                {["auc", "f1", "fpr", "valid_ratio", "alerts_per_kloc", "cross_file_recall", "exploitability_recall"].map((key) => (
                  <span key={key}>{key}: {String(metrics[key])}</span>
                ))}
              </div>
            ) : (
              <p>{task.error ?? "等待评测结果。"}</p>
            )}
          </article>
        );
      })}
    </div>
  );
}

function MetricLine({ name, run }: { name: string; run: Record<string, unknown> }) {
  const metrics = (typeof run.metrics === "object" && run.metrics !== null ? run.metrics : run) as Record<string, unknown>;
  return (
    <div>
      <strong>{name}</strong>
      <div className="metric-line">
        {["auc", "f1", "fpr", "valid_ratio", "alerts_per_kloc", "cross_file_recall", "exploitability_recall"].map((key) => (
          <span key={key}>{key}: {String(metrics[key] ?? "-")}</span>
        ))}
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
