import React, { useEffect, useMemo, useState } from "react";
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

  const refresh = async (preferredScanId?: string) => {
    const [scanData, ruleData, evaluationData] = await Promise.all([api.listScans(), api.rules(), api.listEvaluations()]);
    setScans(scanData);
    setRules(ruleData);
    setEvaluations(evaluationData);
    const activeScan = preferredScanId || selectedScanId || scanData[0]?.id || "";
    setSelectedScanId(activeScan);
    if (activeScan) {
      setFindings(await api.findings(activeScan));
    }
  };

  useEffect(() => {
    refresh().catch((error) => setMessage(error.message));
    const timer = window.setInterval(() => refresh().catch(() => undefined), 3000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      api.findings(selectedScanId).then(setFindings).catch(() => setFindings([]));
    }
  }, [selectedScanId]);

  const dashboard = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed").length;
    const failed = scans.filter((scan) => scan.status === "failed").length;
    const reported = scans.reduce((sum, scan) => sum + Number(scan.summary_json?.reported_count ?? 0), 0);
    const filtered = findings.filter((item) => item.final_decision === "filtered_false_positive").length;
    return { completed, failed, reported, filtered };
  }, [scans, findings]);

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
      setSelectedScanId(task.id);
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
      setSelectedScanId(task.id);
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

        {tab === "dashboard" && (
          <section className="content-grid">
            <MetricCard label="扫描任务" value={scans.length} />
            <MetricCard label="已完成" value={dashboard.completed} tone="success" />
            <MetricCard label="报告漏洞" value={dashboard.reported} tone="danger" />
            <MetricCard label="误报过滤" value={dashboard.filtered} tone="warning" />
            <section className="panel wide">
              <h2>任务概览</h2>
              <TaskTable scans={scans} selectedScanId={selectedScanId} onSelect={setSelectedScanId} />
            </section>
            <section className="panel">
              <h2>严重等级分布</h2>
              <SeverityBars findings={findings} />
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
              <TaskTable scans={scans} selectedScanId={selectedScanId} onSelect={setSelectedScanId} />
            </section>
            <section className="panel wide">
              <h2>漏洞详情</h2>
              {selectedScanId && (
                <div className="download-row">
                  <button onClick={() => api.downloadReport(selectedScanId, "json").catch((error) => setMessage(error.message))}>JSON 报告</button>
                  <button onClick={() => api.downloadReport(selectedScanId, "md").catch((error) => setMessage(error.message))}>Markdown 报告</button>
                </div>
              )}
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
      </section>
    </main>
  );
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
          <span>{String(scan.summary_json?.reported_count ?? "-")} findings</span>
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
  return (
    <div className="finding-list">
      {findings.map((item) => (
        <article className="finding" key={item.candidate_id}>
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
            <span>{item.final_decision}</span>
            <span>confidence {item.final_confidence}</span>
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
                {["auc", "f1", "fpr", "alerts_per_kloc", "cross_file_recall", "exploitability_recall"].map((key) => (
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
        {["auc", "f1", "fpr", "alerts_per_kloc", "cross_file_recall", "exploitability_recall"].map((key) => (
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
