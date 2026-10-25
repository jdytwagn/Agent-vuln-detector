import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/dm-sans/400.css";
import "@fontsource/dm-sans/500.css";
import "@fontsource/dm-sans/600.css";
import "@fontsource/dm-sans/700.css";
import "material-symbols/outlined.css";
import { api, EvaluationTask, Finding, Rule, ScanTask } from "./api/client";
import { Icon } from "./components/Icon";
import { MetricCard } from "./components/MetricCard";
import { StatusPill } from "./components/StatusPill";
import "./styles/app.css";

type Tab = "dashboard" | "scan" | "findings" | "rules" | "evaluation";
type TaskFilter = "all" | "done" | "failed" | "active";

const MODEL_PATH_DEFAULTS: Record<string, string> = {
  codebert: "storage/models/codebert-devign-code-vulnerability-detector-git",
  graphcodebert: "storage/models/graphcodebert-devign-code-vulnerability-detector-git"
};
const DEMO_SOURCE_PATH = "tests/samples";
const METRIC_KEYS = ["auc", "f1", "fpr", "valid_ratio", "alerts_per_kloc", "cross_file_recall", "exploitability_recall", "non_exploit_filter"] as const;

const NAV: Array<{ id: Tab; label: string; icon: string }> = [
  { id: "dashboard", label: "仪表盘", icon: "dashboard" },
  { id: "scan", label: "扫描任务", icon: "radar" },
  { id: "findings", label: "漏洞详情", icon: "security" },
  { id: "rules", label: "规则库", icon: "menu_book" },
  { id: "evaluation", label: "效能评测", icon: "analytics" }
];

const PIPELINE = [
  { index: "01", icon: "tune", title: "预处理", subtitle: "语法树与调用点" },
  { index: "02", icon: "policy", title: "规则召回", subtitle: "危险函数初筛" },
  { index: "03", icon: "route", title: "数据流", subtitle: "源到汇的传播" },
  { index: "04", icon: "model_training", title: "模型打分", subtitle: "只给规则命中打分" },
  { index: "05", icon: "psychology", title: "语义解释", subtitle: "模板或 DeepSeek 说明" },
  { index: "06", icon: "bug_report", title: "可利用性", subtitle: "缓解不会被高分推翻" },
  { index: "07", icon: "verified", title: "融合判定", subtitle: "确认、复核或过滤" }
];

function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [scans, setScans] = useState<ScanTask[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [evaluations, setEvaluations] = useState<EvaluationTask[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const selectedScanIdRef = useRef<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sourcePath, setSourcePath] = useState(DEMO_SOURCE_PATH);
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
  const [refreshing, setRefreshing] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [taskFilter, setTaskFilter] = useState<TaskFilter>("all");
  const [ruleQuery, setRuleQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [standardFilter, setStandardFilter] = useState("all");

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
    if (activeScan) setFindings(await api.findings(activeScan));
    else setFindings([]);
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
    if (!selectedScanId) return;
    api.findings(selectedScanId).then(setFindings).catch(() => setFindings([]));
  }, [selectedScanId]);

  const dashboard = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed" || scan.status === "completed_with_errors").length;
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
    return { completed, ...totals };
  }, [scans]);

  const selectedScan = scans.find((scan) => scan.id === selectedScanId);
  const shownBackend = selectedScan?.model_backend || modelBackend;
  const effectiveModelPath = modelPath.trim() || MODEL_PATH_DEFAULTS[modelBackend] || "";
  const activeCount = scans.filter((scan) => scan.status === "pending" || scan.status === "running").length;
  const visibleFindings = findings.filter((item) => item.final_decision !== "filtered_false_positive");
  const filteredFindings = findings.filter((item) => item.final_decision === "filtered_false_positive");
  const findingCounts = countDecisions(findings);

  const filteredScans = scans.filter((scan) => {
    if (taskFilter === "done") return scan.status === "completed" || scan.status === "completed_with_errors";
    if (taskFilter === "failed") return scan.status === "failed";
    if (taskFilter === "active") return scan.status === "pending" || scan.status === "running";
    return true;
  });

  const owaspGroups = useMemo(() => {
    const groups = new Map<string, number>();
    for (const rule of rules) {
      const key = rule.owasp.split(":")[0] || rule.owasp || "未映射";
      groups.set(key, (groups.get(key) ?? 0) + 1);
    }
    return [...groups.entries()];
  }, [rules]);

  const visibleRules = useMemo(() => {
    const query = ruleQuery.trim().toLowerCase();
    return rules.filter((rule) => {
      if (severityFilter !== "all" && rule.severity.toLowerCase() !== severityFilter) return false;
      const standard = rule.owasp.split(":")[0] || rule.owasp;
      if (standardFilter !== "all" && standard !== standardFilter) return false;
      if (!query) return true;
      return [rule.name, rule.cwe, rule.owasp, rule.rule_id, rule.sink_pattern, rule.description].join(" ").toLowerCase().includes(query);
    });
  }, [rules, ruleQuery, severityFilter, standardFilter]);

  const demoScan = scans.find((scan) => scan.source_path.replace(/\\/g, "/").includes(DEMO_SOURCE_PATH) && scan.status !== "failed");

  const changeBackend = (value: string) => {
    setModelBackend(value);
    if (value === "mock") setStrictModel(false);
  };

  const refreshNow = async () => {
    setRefreshing(true);
    try {
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "刷新失败");
    } finally {
      window.setTimeout(() => setRefreshing(false), 700);
    }
  };

  const startScan = async (targetPath: string, successMessage: string) => {
    setBusy(true);
    try {
      const task = await api.createScan(targetPath, modelBackend, effectiveModelPath, enableLlm, modelBackend !== "mock" && strictModel);
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

  const submitScan = async () => startScan(sourcePath, "已提交扫描任务");
  const submitDemoScan = async () => {
    setSourcePath(DEMO_SOURCE_PATH);
    await startScan(DEMO_SOURCE_PATH, "已提交内置样例扫描");
  };

  const uploadScan = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    try {
      const task = await api.uploadScan(file, modelBackend, effectiveModelPath, enableLlm, modelBackend !== "mock" && strictModel);
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
        modelBackend !== "mock" && strictModel,
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

  const resetEvaluation = () => {
    setManifestPath("evaluation/sample_manifest.json");
    setModelBackend("mock");
    setModelPath("");
    setStrictModel(false);
    setEnableLlm(false);
    setRunBaselineSuite(false);
    setSkipCodeModels(false);
    setGnnEpochs(20);
  };

  const copyModelPath = async () => {
    if (!effectiveModelPath) return;
    try {
      await navigator.clipboard.writeText(effectiveModelPath);
      setMessage("已复制模型路径");
    } catch {
      setMessage("复制失败，请手动选择路径文本");
    }
  };

  return (
    <div className="min-h-screen bg-background text-on-surface font-body antialiased selection:bg-primary/20">
      <aside className="fixed top-0 left-0 z-40 flex h-full w-64 flex-col justify-between border-r border-outline-variant/10 bg-inverse-surface p-4 shadow-sm max-lg:static max-lg:h-auto max-lg:w-full max-lg:flex-row max-lg:items-center max-lg:gap-3">
        <div className="space-y-6 max-lg:flex max-lg:items-center max-lg:gap-4 max-lg:space-y-0">
          <div className="flex items-center gap-3 px-2 pt-2 max-lg:pt-0">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/40 bg-primary/20 text-primary-container">
              <Icon name="shield" className="text-xl" />
            </div>
            <div className="flex flex-col">
              <span className="font-display text-base font-bold leading-tight tracking-wide text-on-tertiary">漏洞检测平台</span>
              <span className="mt-1 font-label text-xs font-medium leading-none tracking-wider text-outline-variant">Agent-based SAST</span>
            </div>
          </div>
          <nav aria-label="主要导航" className="space-y-1.5 max-lg:flex max-lg:gap-1 max-lg:space-y-0 max-lg:overflow-x-auto">
            {NAV.map((item) => {
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-current={active ? "page" : undefined}
                  onClick={() => setTab(item.id)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-left font-label text-sm transition-all duration-150 max-lg:w-auto max-lg:shrink-0 ${
                    active
                      ? "border-l-2 border-primary bg-primary/20 font-semibold text-primary-container"
                      : "text-outline-variant hover:bg-surface-variant/10 hover:text-on-tertiary"
                  }`}
                >
                  <Icon name={item.icon} filled={active} className="text-xl" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
        <div className="border-t border-outline-variant/10 pt-4 max-lg:border-0 max-lg:pt-0">
          <div className="flex items-center justify-between px-3.5 py-2 text-xs text-outline-variant/80">
            <span className="font-label">引擎版本</span>
            <span className="rounded bg-surface-variant/10 px-1.5 py-0.5 font-mono text-outline-variant">0.1.0</span>
          </div>
        </div>
      </aside>

      <div className="page-highlight ml-64 flex min-h-screen flex-col bg-background max-lg:ml-0">
        <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-outline-variant/30 bg-surface-container-low/80 px-8 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-headline text-sm font-medium text-on-surface-variant">
            <span>安全扫描控制台</span>
            <span className="text-outline-variant">/</span>
            <span className="text-base font-bold text-on-background">{titleFor(tab)}</span>
            {tab === "findings" && selectedScan ? (
              <span className="rounded border border-primary/20 bg-surface-variant px-2 py-0.5 font-mono text-[11px] font-medium text-primary" title={selectedScan.id}>
                任务 {selectedScan.id.slice(0, 8)}
              </span>
            ) : null}
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-full border border-outline-variant/30 bg-surface-container-high px-3 py-1 text-xs font-medium text-on-surface-variant sm:flex">
              <span className={`h-2 w-2 rounded-full ${activeCount ? "animate-pulse bg-primary" : "bg-status-green"}`} />
              <span>{activeCount ? `${activeCount} 个任务运行中` : "本地引擎空闲"}</span>
              <span className="font-mono text-primary">{shownBackend}</span>
            </div>
            <div className="mx-1 hidden h-4 w-px bg-outline-variant/40 sm:block" />
            <button type="button" title="刷新" aria-label="刷新数据" onClick={() => void refreshNow()} className="flex h-9 w-9 items-center justify-center rounded-full text-on-surface-variant transition-all duration-150 hover:bg-surface-container hover:text-on-surface active:scale-95">
              <Icon name="refresh" className={`text-xl ${refreshing ? "animate-spin" : ""}`} />
            </button>
            <button type="button" title={message ? "查看最近提示" : "暂无运行提示"} aria-label="运行提示" onClick={() => setNoticeOpen((open) => !open)} className="relative flex h-9 w-9 items-center justify-center rounded-full text-on-surface-variant transition-all duration-150 hover:bg-surface-container hover:text-on-surface active:scale-95">
              <Icon name="notifications" className="text-xl" />
              {message ? <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-error" /> : null}
            </button>
            <button type="button" title="界面说明" aria-label="界面说明" onClick={() => setHelpOpen((open) => !open)} className="flex h-9 w-9 items-center justify-center rounded-full text-on-surface-variant transition-all duration-150 hover:bg-surface-container hover:text-on-surface active:scale-95">
              <Icon name="help" className="text-xl" />
            </button>
            <div className="mx-1 hidden h-4 w-px bg-outline-variant/40 md:block" />
            <div className="hidden items-center gap-2 pl-1 md:flex">
              <div className="flex h-8 w-8 items-center justify-center rounded-full border border-outline-variant/30 bg-secondary-container text-xs font-bold text-on-secondary-container">
                {shownBackend.slice(0, 2).toUpperCase()}
              </div>
              <div className="flex flex-col text-left">
                <span className="text-xs font-bold leading-tight text-on-surface">{shownBackend}</span>
                <span className="font-mono text-[11px] leading-tight text-outline-variant">当前模型</span>
              </div>
            </div>
          </div>
          {helpOpen ? (
            <div className="absolute right-8 top-16 z-50 w-80 rounded-xl border border-outline-variant/40 bg-surface p-4 text-xs leading-relaxed text-on-surface-variant shadow-card">
              <p className="font-semibold text-on-surface">这条链路实际做什么</p>
              <p className="mt-2">扫描依次经过预处理、规则召回、数据流、模型打分、语义解释、可利用性和融合判定。模型只给规则已经命中的位置打分，不能自己发明漏洞。</p>
              <p className="mt-2">调用前若已有长度检查或更安全的接口，高模型分数只会进入待复核，不会直接确认。</p>
            </div>
          ) : null}
          {noticeOpen ? (
            <div className="absolute right-24 top-16 z-50 w-80 rounded-xl border border-outline-variant/40 bg-surface p-4 text-xs leading-relaxed text-on-surface shadow-card">
              <p className="font-semibold">最近一次提示</p>
              <p className="mt-2 text-on-surface-variant">{message || "暂无运行提示。扫描和评测的提交结果会显示在这里。"}</p>
            </div>
          ) : null}
        </header>

        <main key={tab} className="animate-enter mx-auto w-full max-w-[1440px] flex-1 space-y-6 p-8">
          {message ? (
            <div className="flex items-start justify-between gap-3 rounded-xl border border-primary/30 bg-surface px-4 py-3 text-sm text-on-surface shadow-card">
              <span>{message}</span>
              <button type="button" onClick={() => setMessage("")} className="shrink-0 text-xs font-semibold text-primary">关闭</button>
            </div>
          ) : null}

          {tab === "dashboard" && (
            <>
              <div className="flex flex-col gap-4 pb-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="font-headline text-2xl font-bold tracking-tight text-on-background">安全扫描仪表盘</h2>
                    <span className={`h-2 w-2 rounded-full ${activeCount ? "animate-pulse bg-primary" : "bg-status-green"}`} />
                    <span className="text-xs font-medium text-on-surface-variant">{activeCount ? "正在扫描" : "每 3 秒自动刷新"}</span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-on-surface-variant">规则、模型、数据流、语义和可利用性共同形成最终判定。</p>
                </div>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => setFilterOpen((open) => !open)} className="card-elevation inline-flex items-center gap-2 rounded-lg border border-outline-variant/60 bg-surface-container-lowest px-3.5 py-1.5 text-xs font-semibold text-on-surface hover:bg-surface-variant/40">
                    <Icon name="filter_list" className="text-base" />
                    <span>筛选条件</span>
                  </button>
                  <button type="button" onClick={() => setTab("scan")} className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-on-primary shadow-sm transition-colors hover:bg-primary-dim active:scale-95">
                    <Icon name="play_arrow" filled className="text-base" />
                    <span>去提交扫描</span>
                  </button>
                </div>
              </div>
              {filterOpen ? (
                <div className="flex flex-wrap gap-2">
                  {([
                    ["all", "全部任务"],
                    ["done", "已结束"],
                    ["active", "进行中"],
                    ["failed", "失败"]
                  ] as Array<[TaskFilter, string]>).map(([value, label]) => (
                    <button key={value} type="button" onClick={() => setTaskFilter(value)} className={`rounded-md px-2.5 py-1 text-xs font-medium ${taskFilter === value ? "bg-primary text-on-primary" : "bg-surface text-on-surface-variant hover:bg-surface-container"}`}>
                      {label}
                    </button>
                  ))}
                </div>
              ) : null}
              <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-5">
                <MetricCard label="扫描任务" value={scans.length} hint="全部任务" icon="task" />
                <MetricCard label="已完成" value={dashboard.completed} hint={scans.length ? `共 ${scans.length} 个任务` : "尚无任务"} icon="check_circle" tone="success" />
                <MetricCard label="确认漏洞" value={dashboard.confirmed} hint="融合判定为漏洞" icon="warning" tone="danger" />
                <MetricCard label="待复核" value={dashboard.review} hint="模型与缓解不一致" icon="pending" tone="warning" />
                <MetricCard label="误报过滤" value={dashboard.filtered} hint="不计入确认" icon="filter_alt" />
              </section>
              <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                <div className="console-card flex flex-col justify-between rounded-xl p-6 lg:col-span-7">
                  <div>
                    <div className="mb-4 flex items-center justify-between border-b border-surface-variant pb-2">
                      <div className="flex items-center gap-2">
                        <Icon name="format_list_bulleted" className="text-xl text-primary" />
                        <h3 className="font-headline text-base font-bold text-on-background">任务概览</h3>
                      </div>
                      <span className="font-label text-xs text-on-surface-variant">{filteredScans.length} 条符合当前筛选</span>
                    </div>
                    <div className="max-h-[28rem] space-y-3 overflow-y-auto pr-1">
                      {filteredScans.slice(0, 8).map((scan) => (
                        <OverviewRow key={scan.id} scan={scan} selected={scan.id === selectedScanId} onSelect={selectScan} />
                      ))}
                      {!filteredScans.length ? <p className="text-sm text-on-surface-variant">暂无扫描任务。</p> : null}
                    </div>
                  </div>
                  <div className="mt-4 flex items-center justify-between border-t border-surface-variant pt-3 text-xs text-on-surface-variant">
                    <span>{selectedScan ? `当前 ${selectedScan.source_path}` : "尚未选择任务"}</span>
                    <button type="button" onClick={() => setTab("findings")} className="inline-flex items-center gap-1 font-medium text-primary hover:underline">
                      查看全部扫描任务
                      <Icon name="chevron_right" className="text-sm" />
                    </button>
                  </div>
                </div>
                <div className="console-card flex flex-col justify-between rounded-xl p-6 lg:col-span-5">
                  <div>
                    <div className="mb-1 flex items-center gap-2">
                      <Icon name="bar_chart" className="text-xl text-primary" />
                      <h3 className="font-headline text-base font-bold text-on-background">当前任务严重等级</h3>
                    </div>
                    <p className="mb-5 font-label text-xs text-on-surface-variant">
                      {selectedScan?.source_path || "尚未选择任务"}。只统计当前任务未过滤结果。
                    </p>
                    {selectedScan?.status === "failed" ? <p className="mb-4 text-xs text-error">{selectedScan.error || "扫描失败"}</p> : null}
                    <SeverityBars findings={visibleFindings} />
                  </div>
                  <div className="mt-4 flex items-center justify-between border-t border-surface-variant pt-3 text-xs text-on-surface-variant">
                    <span>未过滤 {visibleFindings.length} 项</span>
                    <span className="font-mono">过滤 {filteredFindings.length} 项</span>
                  </div>
                </div>
              </section>
              <PipelinePanel scan={selectedScan} />
            </>
          )}

          {tab === "scan" && (
            <>
              <div className="flex flex-col gap-1 pb-1">
                <h1 className="font-headline text-2xl font-bold tracking-tight text-on-surface">扫描任务</h1>
                <p className="font-label text-sm text-outline">选择源码、模型后端和严格模式，然后提交路径或压缩包。</p>
              </div>
              <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-12">
                <section className="console-card flex h-full flex-col justify-between rounded-xl bg-white p-6 lg:col-span-4">
                  <div className="space-y-5">
                    <div className="flex items-center gap-2.5 border-b border-outline-variant/20 pb-3">
                      <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-surface-container text-primary">
                        <Icon name="bolt" className="text-lg" />
                      </div>
                      <h2 className="font-headline text-base font-bold text-on-surface">快速开始</h2>
                    </div>
                    <p className="text-sm leading-relaxed text-on-surface-variant">先跑仓库里的 C/C++ 样例，确认规则、数据流和融合判定都走到了漏洞详情。</p>
                    <div className="pt-2">
                      <button type="button" disabled={busy} onClick={() => void submitDemoScan()} className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-sm font-medium text-on-primary shadow-sm transition-all duration-150 hover:bg-primary-dim active:scale-[0.99] disabled:opacity-60">
                        <Icon name="play_arrow" filled className="text-xl" />
                        <span>{busy ? "提交中" : "扫描内置样例"}</span>
                      </button>
                      <p className="mt-2.5 text-center text-xs leading-normal text-outline">推荐先跑 tests/samples，完成后自动进入漏洞详情。</p>
                    </div>
                    <div className="inset-surface mt-4 space-y-3 rounded-lg p-4">
                      <div className="flex items-center justify-between text-xs font-semibold text-on-surface">
                        <span className="flex items-center gap-1.5">
                          <Icon name="folder_open" className="text-base text-primary" />
                          tests/samples
                        </span>
                        <span className="font-mono text-[11px] text-outline-variant">C / C++</span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-on-surface-variant">
                        <li>未检查边界的 strcpy</li>
                        <li>调用前有长度检查的 strcpy</li>
                        <li>跨文件传入 system</li>
                      </ul>
                      {demoScan ? <p className="border-t border-outline-variant/20 pt-2 text-[11px] text-on-surface-variant">最近一次：{formatScanCounts(demoScan)}</p> : <p className="text-[11px] text-outline">还没有成功跑过这个目录。</p>}
                    </div>
                  </div>
                  <div className="mt-6 flex items-center justify-between border-t border-outline-variant/20 pt-5 font-mono text-xs text-outline">
                    <span>rules/cwe_rules.yaml</span>
                    <span>{rules.length} 条规则</span>
                  </div>
                </section>
                <section className="console-card rounded-xl bg-white p-6 lg:col-span-8">
                  <form className="space-y-5" onSubmit={(event) => { event.preventDefault(); void submitScan(); }}>
                    <div className="flex items-center justify-between border-b border-outline-variant/20 pb-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <Icon name="terminal" className="text-xl text-primary" />
                          <h2 className="font-headline text-base font-bold text-on-surface">提交扫描</h2>
                        </div>
                        <p className="mt-0.5 font-label text-xs text-outline">路径、后端和两个可选开关</p>
                      </div>
                      <span className="rounded bg-surface-container px-2 py-1 font-mono text-xs text-outline-variant">顺序流水线</span>
                    </div>
                    <div className="space-y-1.5">
                      <label className="block text-xs font-semibold text-on-surface" htmlFor="source-path">源码路径 <span className="text-error">*</span></label>
                      <div className="inset-surface flex items-center gap-3 rounded-lg px-3.5 py-2.5">
                        <Icon name="folder_open" className="text-lg text-outline-variant" />
                        <input id="source-path" value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} className="w-full border-0 bg-transparent p-0 font-mono text-sm text-on-surface placeholder:text-outline-variant focus:ring-0" />
                        <span className="rounded border border-outline-variant/30 bg-white/80 px-1.5 py-0.5 font-mono text-[11px] uppercase text-outline-variant">工作区</span>
                      </div>
                      <p className="text-[11px] text-outline">相对仓库根目录，或后端允许的绝对路径。</p>
                    </div>
                    <div className="space-y-1.5">
                      <label className="block text-xs font-semibold text-on-surface" htmlFor="model-backend">模型后端 <span className="text-error">*</span></label>
                      <div className="relative inset-surface rounded-lg">
                        <select id="model-backend" value={modelBackend} onChange={(event) => changeBackend(event.target.value)} className="w-full cursor-pointer appearance-none border-0 bg-transparent py-2.5 pl-3.5 pr-10 text-sm font-medium text-on-surface focus:ring-0">
                          <option value="mock">mock（不加载权重）</option>
                          <option value="codebert">CodeBERT（Devign 序列分类）</option>
                          <option value="graphcodebert">GraphCodeBERT（Devign 序列分类）</option>
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-outline">
                          <Icon name="expand_more" className="text-lg" />
                        </div>
                      </div>
                    </div>
                    {modelBackend !== "mock" ? (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <label className="block text-xs font-semibold text-on-surface" htmlFor="model-path">模型路径</label>
                          <span className="font-mono text-[11px] text-outline">留空使用默认目录</span>
                        </div>
                        <div className="inset-surface flex items-center gap-2.5 rounded-lg px-3.5 py-2.5">
                          <Icon name="memory" className="text-lg text-outline-variant" />
                          <input id="model-path" value={modelPath} placeholder={MODEL_PATH_DEFAULTS[modelBackend]} onChange={(event) => setModelPath(event.target.value)} className="w-full border-0 bg-transparent p-0 font-mono text-xs text-on-surface focus:ring-0" />
                          <button type="button" title="复制路径" onClick={() => void copyModelPath()} className="text-outline hover:text-primary">
                            <Icon name="content_copy" className="text-base" />
                          </button>
                        </div>
                      </div>
                    ) : null}
                    <div className="space-y-3 pt-2">
                      <span className="block text-xs font-semibold text-on-surface">高级检测开关</span>
                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                        {modelBackend !== "mock" ? (
                          <CheckCard checked={strictModel} onChange={setStrictModel} title="严格模型模式" description="权重无法加载时任务失败，不降级为 mock。" />
                        ) : null}
                        <CheckCard checked={enableLlm} onChange={setEnableLlm} title="启用 DeepSeek 语义推理" description="用 DeepSeek 写语义说明。未配置密钥时仍使用模板说明。" />
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-outline-variant/20 pt-4">
                      <div className="flex items-center gap-2 text-xs text-outline">
                        <Icon name="memory" className="text-base text-outline-variant" />
                        <span>由本机后端进程执行</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-primary px-4 py-2.5 text-xs font-medium text-primary transition-colors hover:bg-primary/10">
                          <Icon name="cloud_upload" className="text-base" />
                          <span>上传压缩包</span>
                          <input type="file" accept=".zip,.c,.cc,.cpp,.cxx,.h,.hpp" className="sr-only" onChange={(event) => void uploadScan(event)} />
                        </label>
                        <button type="submit" disabled={busy} className="flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-xs font-medium text-on-primary shadow-sm transition-all hover:bg-primary-dim active:scale-95 disabled:opacity-60">
                          <Icon name="radar" className="text-base" />
                          <span>{busy ? "提交中" : "扫描路径"}</span>
                        </button>
                      </div>
                    </div>
                  </form>
                </section>
              </div>
              <div className="console-card flex flex-wrap items-center justify-between gap-4 rounded-xl bg-white/90 p-4 text-xs">
                <div className="flex flex-wrap items-center gap-6">
                  <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-primary" /><span className="text-outline">模型后端</span><span className="font-mono font-semibold text-on-surface">{modelBackend}</span></span>
                  <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-secondary" /><span className="text-outline">严格模式</span><span className="font-mono font-semibold text-on-surface">{modelBackend !== "mock" && strictModel ? "开" : "关"}</span></span>
                  <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-status-amber" /><span className="text-outline">DeepSeek</span><span className="font-mono font-semibold text-on-surface">{enableLlm ? "请求开启" : "关"}</span></span>
                </div>
              </div>
            </>
          )}

          {tab === "findings" && (
            <>
              <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-outline-variant/20 pb-6">
                <div>
                  <h2 className="font-headline text-2xl font-bold tracking-tight text-on-surface">证据链与漏洞详情</h2>
                  <p className="mt-1.5 text-sm text-on-surface-variant">规则命中、数据流步骤、模型分数和融合结论。</p>
                </div>
                <div className="flex items-center gap-3">
                  <button type="button" disabled={!selectedScanId} onClick={() => selectedScanId && api.downloadReport(selectedScanId, "json").catch((error) => setMessage(error.message))} className="inline-flex items-center gap-2 rounded-lg border border-primary bg-surface-container-lowest px-3.5 py-2 text-xs font-semibold text-primary shadow-sm transition-all hover:bg-primary-container/20 active:scale-95 disabled:opacity-50">
                    <Icon name="data_object" className="text-[17px]" />
                    <span>JSON 报告</span>
                  </button>
                  <button type="button" disabled={!selectedScanId} onClick={() => selectedScanId && api.downloadReport(selectedScanId, "md").catch((error) => setMessage(error.message))} className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-on-primary shadow-sm transition-all hover:bg-primary-dim active:scale-95 disabled:opacity-50">
                    <Icon name="description" className="text-[17px]" />
                    <span>Markdown 报告</span>
                  </button>
                </div>
              </div>
              <div className="grid grid-cols-12 items-start gap-6">
                <div className="col-span-12 space-y-4 lg:sticky lg:top-20 lg:col-span-4 lg:self-start">
                  <div className="console-card rounded-xl border border-outline-variant/30 p-5">
                    <div className="mb-4 flex items-center justify-between border-b border-outline-variant/20 pb-3.5">
                      <div className="flex items-center gap-2">
                        <Icon name="view_list" className="text-[19px] text-primary" />
                        <h3 className="font-headline text-sm font-bold text-on-surface">扫描任务</h3>
                      </div>
                      <span className="font-mono text-xs text-outline">共 {scans.length} 个</span>
                    </div>
                    <div className="max-h-[36rem] space-y-3 overflow-y-auto pr-1">
                      {scans.map((scan) => (
                        <FindingTaskCard key={scan.id} scan={scan} selected={scan.id === selectedScanId} onSelect={selectScan} />
                      ))}
                      {!scans.length ? <p className="text-sm text-on-surface-variant">暂无扫描任务。</p> : null}
                    </div>
                  </div>
                  <div className="console-card rounded-xl p-4 text-xs text-on-surface-variant">
                    <div className="mb-2 flex items-center gap-1.5 font-bold text-on-surface">
                      <Icon name="info" className="text-base text-primary" />
                      <span>证据链判定标准</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-outline">危险调用先由规则召回，再看数据流是否从源到达汇、调用前有没有缓解。模型分数不能把已缓解的调用直接确认成漏洞。</p>
                  </div>
                </div>
                <div className="col-span-12 space-y-6 lg:col-span-8">
                  <div className="console-card flex flex-wrap items-center justify-between gap-3 rounded-xl p-4">
                    <div className="flex items-center gap-2">
                      <h3 className="font-headline text-base font-bold text-on-surface">漏洞详情</h3>
                      <span className="text-xs text-outline">|</span>
                      <span className="max-w-[18rem] truncate font-mono text-xs text-on-surface-variant">{selectedScan?.source_path || "未选择任务"}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-md border border-outline-variant/30 bg-surface-container px-2.5 py-1 font-mono text-xs text-on-surface">结果 <span className="font-bold">{findings.length}</span></span>
                      <span className="rounded-md border border-error/30 bg-red-50 px-2.5 py-1 font-mono text-xs font-semibold text-error">确认漏洞 <span className="font-bold">{findingCounts.vulnerable}</span></span>
                      <button
                        type="button"
                        onClick={() => {
                          const review = findings.find((item) => item.final_decision === "needs_review");
                          if (!review) return;
                          document.getElementById(`finding-${review.candidate_id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
                        }}
                        className="rounded-md border border-status-amber/30 bg-amber-50 px-2.5 py-1 font-mono text-xs font-semibold text-status-amber"
                      >
                        待复核 <span className="font-bold">{findingCounts.needs_review}</span>
                      </button>
                    </div>
                  </div>
                  {selectedScan?.error ? <p className="rounded-lg border border-error/30 bg-red-50 px-4 py-3 text-sm text-error">{selectedScan.error}</p> : null}
                  {selectedScan?.summary_json?.model_fallback ? (
                    <div className="rounded-lg border border-status-amber/40 bg-amber-50 px-4 py-3 text-sm text-status-amber">模型未能加载，本次结果已降级为 mock：{String(selectedScan.summary_json.model_load_error ?? "")}</div>
                  ) : null}
                  {selectedScan?.summary_json?.parser_fallback ? (
                    <div className="rounded-lg border border-status-amber/40 bg-amber-50 px-4 py-3 text-sm text-status-amber">Tree-sitter 不可用，预处理已退回轻量解析：{String(selectedScan.summary_json.parser_error ?? "")}</div>
                  ) : null}
                  <FindingList findings={findings} />
                </div>
              </div>
            </>
          )}

          {tab === "rules" && (
            <>
              <section className="flex flex-col justify-between gap-4 pb-2 md:flex-row md:items-center">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="font-headline text-2xl font-bold tracking-tight text-on-background">规则库</h2>
                    <span className="rounded-full border border-primary/20 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary">内置污点汇聚点</span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-on-surface-variant">这些规则来自仓库里的 CWE / OWASP 清单，扫描时全部参与召回。</p>
                </div>
                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="flex items-center gap-2 rounded-lg border border-outline-variant/30 bg-surface-variant px-3.5 py-1.5">
                    <span className="text-xs text-on-surface-variant">规则总数</span>
                    <span className="font-mono text-sm font-bold text-on-surface">{rules.length}</span>
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-outline-variant/30 bg-surface-variant px-3.5 py-1.5">
                    <span className="h-2 w-2 rounded-full bg-status-green" />
                    <span className="text-xs text-on-surface-variant">当前显示</span>
                    <span className="font-mono text-sm font-bold text-primary">{visibleRules.length}</span>
                  </div>
                </div>
              </section>
              <div className="console-card flex flex-col items-center justify-between gap-3 rounded-lg p-3.5 md:flex-row">
                <div className="relative w-full md:w-80">
                  <Icon name="search" className="absolute left-3 top-2 text-lg text-on-surface-variant" />
                  <input value={ruleQuery} onChange={(event) => setRuleQuery(event.target.value)} placeholder="搜索规则名、CWE 编号、危险函数" className="w-full rounded-md border border-outline-variant/40 bg-surface-variant py-1.5 pl-9 pr-3 text-xs text-on-surface placeholder:text-outline-variant focus:border-primary focus:bg-white focus:outline-none" />
                </div>
                <div className="flex w-full items-center gap-4 overflow-x-auto md:w-auto">
                  <div className="flex items-center gap-1 text-xs">
                    <span className="mr-1.5 whitespace-nowrap font-medium text-on-surface-variant">危险级别</span>
                    {["all", "critical", "high", "medium", "low"].map((level) => (
                      <button key={level} type="button" onClick={() => setSeverityFilter(level)} className={`whitespace-nowrap rounded-md px-2.5 py-1 text-xs font-medium ${severityFilter === level ? "bg-primary text-on-primary" : "text-on-surface-variant hover:bg-surface-container"}`}>
                        {level === "all" ? "全部" : level.toUpperCase()}
                      </button>
                    ))}
                  </div>
                  <div className="h-4 w-px shrink-0 bg-outline-variant/30" />
                  <div className="flex items-center gap-1 text-xs">
                    <span className="mr-1.5 whitespace-nowrap font-medium text-on-surface-variant">OWASP</span>
                    <button type="button" onClick={() => setStandardFilter("all")} className={`rounded-md border px-2.5 py-1 text-xs font-medium ${standardFilter === "all" ? "border-outline-variant/40 bg-surface-container-high text-on-surface" : "border-outline-variant/30 bg-surface-container text-on-surface-variant"}`}>全部</button>
                    {owaspGroups.map(([name]) => (
                      <button key={name} type="button" onClick={() => setStandardFilter(name)} className={`whitespace-nowrap rounded-md border px-2.5 py-1 font-mono text-xs font-medium ${standardFilter === name ? "border-primary/40 bg-primary/10 text-primary" : "border-outline-variant/30 bg-surface-container text-on-surface-variant"}`}>
                        {name}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="console-card space-y-5 rounded-lg p-6">
                <div className="flex flex-col justify-between gap-2 border-b border-outline-variant/20 pb-4 sm:flex-row sm:items-center">
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="font-headline text-lg font-bold text-on-background">CWE / OWASP 规则库</h3>
                    <span className="rounded border border-outline-variant/30 bg-surface-container px-2.5 py-0.5 font-mono text-[11px] text-on-surface-variant">已加载 {rules.length} 条</span>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {visibleRules.map((rule) => (
                    <article key={rule.rule_id} className="rule-card flex flex-col justify-between rounded-lg p-4">
                      <div>
                        <div className="mb-2 flex items-start justify-between gap-2">
                          <h4 className="text-sm font-bold leading-snug text-on-background">{rule.name}</h4>
                          <span className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-bold tracking-wide ${severityBadge(rule.severity)}`}>{rule.severity.toUpperCase()}</span>
                        </div>
                        <div className="mb-3 flex flex-wrap items-center gap-2">
                          <span className="rounded bg-surface-container px-1.5 py-0.5 font-mono text-[11px] font-medium text-secondary">{rule.cwe}</span>
                          <span className="rounded border border-primary/20 bg-primary-container/30 px-2 py-0.5 font-mono text-xs font-bold text-primary">{rule.sink_pattern}</span>
                        </div>
                        <p className="mb-4 text-xs leading-relaxed text-on-surface-variant">{rule.description}</p>
                      </div>
                      <div className="flex items-center justify-between border-t border-outline-variant/20 pt-3">
                        <span className="font-mono text-[11px] text-outline">{rule.owasp}</span>
                        <span className="font-mono text-[11px] text-outline-variant">{rule.rule_id}</span>
                      </div>
                    </article>
                  ))}
                </div>
                {!visibleRules.length ? <p className="text-sm text-on-surface-variant">没有符合筛选条件的规则。</p> : null}
                <div className="border-t border-outline-variant/20 pt-4 text-xs text-on-surface-variant">
                  显示 {visibleRules.length} 项，共 {rules.length} 项。规则随扫描全部启用，这里不能单独停用。
                </div>
              </div>
            </>
          )}

          {tab === "evaluation" && (
            <>
              <div className="flex flex-col gap-4 border-b border-outline-variant/30 pb-2 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="font-headline text-2xl font-bold tracking-tight text-on-surface">实验评测</h2>
                  <p className="mt-1 font-label text-sm text-on-surface-variant">用清单跑当前流水线，需要时再加基线对照。</p>
                </div>
                <div className="inline-flex items-center gap-2 rounded-lg border border-outline-variant/40 bg-white/70 px-3 py-1.5 text-xs text-on-surface-variant">
                  <Icon name="description" className="text-sm text-primary" />
                  <span>清单 <span className="font-mono font-medium text-on-surface">{manifestPath}</span></span>
                </div>
              </div>
              <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-12">
                <section className="console-card flex flex-col gap-6 rounded-xl p-6 lg:col-span-5">
                  <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-container text-primary">
                        <Icon name="tune" className="text-base" />
                      </div>
                      <div>
                        <h3 className="font-headline text-base font-bold text-on-surface">提交评测</h3>
                        <p className="font-label text-xs text-outline">清单、后端和基线开关</p>
                      </div>
                    </div>
                  </div>
                  <form className="flex flex-col gap-5" onSubmit={(event) => { event.preventDefault(); void submitEvaluation(); }}>
                    <div className="flex flex-col gap-1.5">
                      <label className="flex items-center justify-between text-xs font-semibold text-on-surface">
                        <span>评测清单路径</span>
                        <span className="text-[11px] font-normal text-outline">JSON</span>
                      </label>
                      <div className="inset-surface flex items-center gap-2 rounded-lg px-3 py-2.5">
                        <Icon name="description" className="text-lg text-outline" />
                        <input value={manifestPath} onChange={(event) => setManifestPath(event.target.value)} className="w-full border-0 bg-transparent p-0 font-mono text-xs text-on-surface focus:ring-0" />
                      </div>
                    </div>
                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs font-semibold text-on-surface">模型推理后端</label>
                      <div className="relative">
                        <select value={modelBackend} onChange={(event) => changeBackend(event.target.value)} className="w-full cursor-pointer appearance-none rounded-lg border border-outline-variant/40 bg-surface-variant px-3.5 py-2.5 pr-9 text-xs text-on-surface focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary">
                          <option value="mock">mock（不加载权重）</option>
                          <option value="codebert">CodeBERT（Devign 序列分类）</option>
                          <option value="graphcodebert">GraphCodeBERT（Devign 序列分类）</option>
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-outline">
                          <Icon name="expand_more" className="text-base" />
                        </div>
                      </div>
                    </div>
                    {modelBackend !== "mock" ? (
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs font-semibold text-on-surface">模型路径</label>
                        <input value={modelPath} placeholder={MODEL_PATH_DEFAULTS[modelBackend]} onChange={(event) => setModelPath(event.target.value)} className="rounded-lg border border-outline-variant/40 bg-surface-variant px-3.5 py-2.5 font-mono text-xs text-on-surface focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary" />
                      </div>
                    ) : null}
                    <div className="flex flex-col gap-2.5 pt-1">
                      <span className="text-xs font-semibold text-on-surface">评测策略与开关</span>
                      {modelBackend !== "mock" ? (
                        <Toggle checked={strictModel} onChange={setStrictModel} title="严格模型模式" description="权重无法加载时任务失败，不降级为 mock。" />
                      ) : null}
                      <Toggle checked={enableLlm} onChange={setEnableLlm} title="启用 DeepSeek 语义推理" description="为每条命中请求语义说明。未配置密钥时仍使用模板。" />
                      <Toggle checked={runBaselineSuite} onChange={setRunBaselineSuite} title="运行完整基线套件" description="同时跑规则、图特征和可选的代码模型、GNN 对照。" />
                      {runBaselineSuite ? (
                        <>
                          <Toggle checked={skipCodeModels} onChange={setSkipCodeModels} title="跳过 CodeBERT / GraphCodeBERT 纯模型基线" description="套件里不单独加载这两套权重。" />
                          <label className="flex items-center justify-between gap-3 rounded-lg border border-outline-variant/30 bg-surface-variant p-3 text-xs">
                            <span className="font-semibold text-on-surface">GNN 训练轮次</span>
                            <input type="number" min={1} max={200} value={gnnEpochs} onChange={(event) => setGnnEpochs(Number(event.target.value) || 1)} className="w-24 rounded-md border border-outline-variant/40 bg-white px-2 py-1 text-right font-mono text-xs focus:border-primary focus:ring-1 focus:ring-primary" />
                          </label>
                        </>
                      ) : null}
                    </div>
                    <div className="flex items-center justify-between gap-3 border-t border-outline-variant/20 pt-4">
                      <button type="button" onClick={resetEvaluation} className="rounded-lg border border-outline-variant/40 px-4 py-2 text-xs font-medium text-on-surface-variant hover:bg-surface-container hover:text-on-surface">重置</button>
                      <button type="submit" disabled={busy} className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2 text-xs font-semibold text-on-primary shadow-sm transition-all hover:bg-primary-dim active:scale-95 disabled:opacity-60">
                        <Icon name="play_arrow" className="text-base" />
                        <span>{busy ? "提交中" : "启动评测"}</span>
                      </button>
                    </div>
                  </form>
                </section>
                <section className="flex flex-col gap-6 lg:col-span-7">
                  {evaluations.length ? [...evaluations].reverse().map((task) => <EvaluationCard key={task.id} task={task} />) : (
                    <div className="console-card rounded-xl p-6 text-sm text-on-surface-variant">暂无评测任务。</div>
                  )}
                </section>
              </div>
            </>
          )}
        </main>
        <footer className="flex h-10 items-center justify-between border-t border-outline-variant/30 bg-surface-container-low/60 px-8 text-[11px] text-on-surface-variant">
          <span>本地控制台 · 数据来自当前工作区</span>
          <span>漏洞检测平台 0.1.0</span>
        </footer>
      </div>
    </div>
  );
}

function CheckCard({ checked, onChange, title, description }: { checked: boolean; onChange: (value: boolean) => void; title: string; description: string }) {
  return (
    <label className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${checked ? "border-primary/40 bg-surface-container-low/60" : "border-outline-variant/30 hover:bg-surface-container-low/40"}`}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="mt-0.5 h-4 w-4 rounded border-outline-variant text-primary focus:ring-primary" />
      <span className="text-xs">
        <span className="block font-bold text-on-surface">{title}</span>
        <span className="mt-0.5 block text-[11px] leading-relaxed text-outline">{description}</span>
      </span>
    </label>
  );
}

function Toggle({ checked, onChange, title, description }: { checked: boolean; onChange: (value: boolean) => void; title: string; description: string }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-3 rounded-lg border border-outline-variant/30 bg-surface-variant p-3">
      <span className="flex flex-col">
        <span className="text-xs font-semibold text-on-surface">{title}</span>
        <span className="mt-0.5 text-[11px] leading-relaxed text-outline">{description}</span>
      </span>
      <span className="relative mt-0.5 inline-flex shrink-0 items-center">
        <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="peer sr-only" />
        <span className="relative h-5 w-9 rounded-full bg-outline-variant/70 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform after:content-[''] peer-checked:bg-primary peer-checked:after:translate-x-4" />
      </span>
    </label>
  );
}

function OverviewRow({ scan, selected, onSelect }: { scan: ScanTask; selected: boolean; onSelect: (id: string) => void }) {
  const counts = splitCounts(scan);
  return (
    <button type="button" onClick={() => onSelect(scan.id)} className={`sunken-panel relative w-full overflow-hidden rounded-lg bg-surface-variant p-4 text-left transition-all duration-150 ${selected ? "border border-primary/40" : "border border-outline-variant/20 hover:border-primary/30"}`}>
      {selected ? <span className="absolute bottom-0 left-0 top-0 w-1 bg-primary" /> : null}
      <span className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <span className="min-w-0 space-y-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="truncate font-mono text-sm font-semibold text-on-background">{scan.source_path}</span>
            <StatusPill status={scan.status} />
          </span>
          <span className="flex flex-wrap items-center gap-3 text-xs text-on-surface-variant">
            <span>{formatTime(scan.created_at)}</span>
            <span className="font-mono">{scan.model_backend}</span>
          </span>
        </span>
        {scan.status === "failed" ? (
          <span className="max-w-xs text-left font-mono text-xs text-error sm:text-right">{scan.error || "扫描失败"}</span>
        ) : (
          <span className="inline-flex items-center gap-2 self-start rounded border border-outline-variant/30 bg-surface px-3 py-1.5 text-xs font-medium text-on-surface shadow-sm sm:self-auto">
            <span className="inline-block h-2 w-2 rounded-full bg-error" />
            <span>确认 {counts.confirmed}</span>
            <span className="text-outline-variant/60">|</span>
            <span className="inline-block h-2 w-2 rounded-full bg-status-amber" />
            <span>复核 {counts.review}</span>
          </span>
        )}
      </span>
    </button>
  );
}

function FindingTaskCard({ scan, selected, onSelect }: { scan: ScanTask; selected: boolean; onSelect: (id: string) => void }) {
  const counts = splitCounts(scan);
  const files = summaryNumber(scan.summary_json, "files_scanned");
  return (
    <button type="button" onClick={() => onSelect(scan.id)} className={`w-full rounded-lg p-3.5 text-left transition-all duration-150 ${selected ? "relative border-2 border-primary/40 bg-primary/5 shadow-sm" : "border border-outline-variant/20 bg-surface-container-low hover:border-outline-variant/50"}`}>
      <span className="mb-2 flex items-start justify-between gap-2">
        <span className="flex min-w-0 items-center gap-1.5">
          <Icon name={scan.source_path.includes(".") && !scan.source_path.endsWith("/") ? "description" : "folder_open"} className={`shrink-0 text-[17px] ${selected ? "text-primary" : "text-outline"}`} />
          <span className="truncate font-mono text-xs font-bold text-on-surface">{scan.source_path}</span>
        </span>
        <StatusPill status={scan.status} />
      </span>
      {scan.status === "failed" ? (
        <span className="block text-left text-[11px] text-error">{scan.error || "扫描失败"}</span>
      ) : (
        <span className="my-2.5 grid grid-cols-2 gap-2 rounded border border-outline-variant/20 bg-white/80 p-2">
          <span className="text-[11px] text-on-surface-variant">确认 <span className="font-mono text-sm font-bold text-error">{counts.confirmed}</span></span>
          <span className="text-[11px] text-on-surface-variant">复核 <span className="font-mono text-sm font-bold text-status-amber">{counts.review}</span></span>
        </span>
      )}
      <span className="mt-1 flex items-center justify-between border-t border-outline-variant/15 pt-1 font-mono text-[11px] text-outline">
        <span>{scan.model_backend}</span>
        <span>{files === null ? formatTime(scan.created_at) : `${files} 个文件`}</span>
      </span>
    </button>
  );
}

function SeverityBars({ findings }: { findings: Finding[] }) {
  const levels = [
    { id: "critical", className: "text-error" },
    { id: "high", className: "text-status-amber" },
    { id: "medium", className: "text-status-amber" },
    { id: "low", className: "text-on-surface-variant" }
  ];
  const max = Math.max(1, ...levels.map((level) => findings.filter((item) => item.final_severity === level.id).length));
  return (
    <div className="space-y-4">
      {levels.map((level) => {
        const count = findings.filter((item) => item.final_severity === level.id).length;
        return (
          <div key={level.id}>
            <div className="mb-1.5 flex items-center justify-between text-xs font-medium">
              <span className={`flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider ${count ? level.className : "text-on-surface-variant"}`}>
                <span className={`h-2 w-2 rounded-full ${count ? "bg-current" : "bg-outline-variant"}`} />
                {level.id}
              </span>
              <span className="font-mono font-bold text-on-background">{count}</span>
            </div>
            <div className="sunken-panel h-2.5 w-full overflow-hidden rounded bg-surface-variant">
              <div className="h-full rounded bg-primary transition-all duration-500 ease-out" style={{ width: `${(count / max) * 100}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PipelinePanel({ scan }: { scan?: ScanTask }) {
  const summary = scan?.summary_json;
  const running = scan?.status === "pending" || scan?.status === "running";
  const feet = pipelineFeet(scan);
  return (
    <section className="console-card relative overflow-hidden rounded-xl p-6">
      <div className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon name="hub" className="text-xl text-primary" />
          <h3 className="font-headline text-base font-bold text-on-background">判定链路</h3>
          <span className="ml-2 font-label text-xs text-on-surface-variant">七步顺序流水线</span>
        </div>
        <div className={`flex items-center gap-2 text-xs font-medium ${running ? "text-primary" : scan?.status === "failed" ? "text-error" : "text-status-green"}`}>
          <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse bg-primary" : scan?.status === "failed" ? "bg-error" : "bg-status-green"}`} />
          <span>{running ? "所选任务运行中" : scan?.status === "failed" ? "所选任务失败" : scan ? "数字来自所选任务" : "还没有任务"}</span>
        </div>
      </div>
      <div className="relative px-1 py-2">
        <div className="pointer-events-none absolute inset-0 z-10 overflow-hidden">
          <div className="animate-scan-beam h-full w-24 bg-gradient-to-r from-transparent via-primary-container/50 to-transparent" />
        </div>
        <div className="relative z-0 grid grid-cols-1 gap-3 md:grid-cols-7">
          {PIPELINE.map((step, index) => {
            const last = index === PIPELINE.length - 1;
            return (
              <div key={step.index} className={`sunken-panel flex flex-col justify-between rounded-lg bg-surface-variant p-3.5 ${last ? "border-2 border-primary bg-primary/5" : "border border-outline-variant/30 hover:border-primary/50"}`}>
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-primary">{step.index}</span>
                  <Icon name={step.icon} className={`text-sm ${last ? "text-primary" : "text-outline"}`} />
                </div>
                <div>
                  <h4 className={`text-xs font-bold ${last ? "text-primary" : "text-on-background"}`}>{step.title}</h4>
                  <p className="mt-1 text-[11px] leading-tight text-on-surface-variant">{step.subtitle}</p>
                </div>
                <div className={`mt-3 flex items-center justify-between border-t pt-2 font-mono text-[10px] ${last ? "border-primary/20 text-primary" : "border-outline-variant/20 text-on-surface-variant"}`}>
                  <span className="truncate">{feet[index]}</span>
                  <Icon name={summary ? "done" : "hourglass_empty"} className="text-xs" />
                </div>
              </div>
            );
          })}
        </div>
        <div className="hidden items-center justify-between px-12 pt-3 text-outline-variant md:flex">
          {Array.from({ length: 6 }, (_, index) => <Icon key={index} name="arrow_forward" className="text-sm" />)}
        </div>
      </div>
      <div className="mt-4 rounded-lg border border-outline-variant/20 bg-code-bg p-3.5 font-mono text-xs text-code-text shadow-inner">
        <div className="mb-2 flex items-center justify-between border-b border-outline-variant/20 pb-2 text-[11px] text-outline-variant">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full bg-status-green" />
            {scan ? scan.source_path : "尚未选择任务"}
          </span>
          <span>{scan ? scan.model_backend : "无摘要"}</span>
        </div>
        <div className="space-y-1">
          {traceLines(scan).map((line) => <p key={line}>{line}</p>)}
        </div>
      </div>
    </section>
  );
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <p className="rounded-xl border border-outline-variant/30 bg-surface px-4 py-6 text-sm text-on-surface-variant">当前任务暂无可展示漏洞。</p>;
  const filteredCount = findings.filter((item) => item.final_decision === "filtered_false_positive").length;
  const ordered = [...findings].sort((left, right) => decisionRank(left.final_decision) - decisionRank(right.final_decision));
  return (
    <div className="space-y-6">
      {filteredCount > 0 ? <p className="text-xs text-on-surface-variant">另有 {filteredCount} 条因缓解被过滤，仍保留在下面供核对，不计入确认漏洞。</p> : null}
      {ordered.map((item) => <FindingArticle key={item.candidate_id} item={item} />)}
    </div>
  );
}

function FindingArticle({ item }: { item: Finding }) {
  const filtered = item.final_decision === "filtered_false_positive";
  const review = item.final_decision === "needs_review";
  const steps = item.dataflow?.steps ?? [];
  return (
    <article id={`finding-${item.candidate_id}`} className={`console-card relative overflow-hidden rounded-xl border border-outline-variant/30 p-6 ${filtered ? "opacity-70" : ""}`}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <span className={`rounded border px-2 py-0.5 font-mono text-xs font-bold ${review || filtered ? "border-outline-variant/30 bg-surface-container text-secondary" : "border-primary/20 bg-primary/10 text-primary"}`}>{item.candidate_id}</span>
            <h4 className="font-headline text-lg font-bold text-on-surface">{item.rule_evidence.name}</h4>
          </div>
          <div className="mt-1.5 flex items-center gap-2 font-mono text-xs text-on-surface-variant">
            <Icon name="location_on" className="text-[15px] text-outline" />
            <span>{item.file_path}:{item.line} · {item.function_name}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded-full px-3 py-1 text-xs font-black uppercase tracking-wider ${severityPill(item.final_severity)}`}>{item.final_severity}</span>
          {review ? <span className="rounded-full border border-status-amber/40 bg-amber-100 px-2.5 py-0.5 text-xs font-semibold text-status-amber">待复核</span> : null}
        </div>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-2 border-b border-outline-variant/20 pb-4">
        <span className="rounded border border-outline-variant/30 bg-surface-container px-2.5 py-0.5 font-mono text-xs text-on-surface-variant">{item.rule_evidence.cwe}</span>
        {item.rule_evidence.owasp ? <span className="rounded border border-outline-variant/30 bg-surface-container px-2.5 py-0.5 font-mono text-xs text-on-surface-variant">{item.rule_evidence.owasp}</span> : null}
        <span className={`rounded border px-2.5 py-0.5 text-xs font-medium ${decisionTone(item.final_decision)}`}>{decisionLabel(item.final_decision)}</span>
        <span className="rounded border border-primary/30 bg-primary/10 px-2.5 py-0.5 font-mono text-xs font-semibold text-primary">置信度 {item.final_confidence}</span>
        {item.model_score ? <span className="rounded border border-outline-variant/30 bg-slate-100 px-2.5 py-0.5 font-mono text-xs text-on-surface-variant">模型 {item.model_score.score}</span> : null}
      </div>
      <div className="mb-5 overflow-hidden rounded-lg border border-black/40 bg-code-bg shadow-inner">
        <div className="flex items-center justify-between bg-black/40 px-4 py-1.5 font-mono text-[11px] text-outline-variant">
          <span>{item.file_path}:{item.line}</span>
          <span>{item.sink}</span>
        </div>
        <pre className={`overflow-x-auto p-3.5 font-mono text-xs leading-relaxed text-code-text ${review ? "border-l-2 border-status-amber" : filtered ? "border-l-2 border-outline" : "border-l-2 border-error"}`}>{item.code}</pre>
      </div>
      <div className="mb-5">
        <div className="mb-2.5 flex items-center justify-between text-xs font-bold text-on-surface">
          <span className="flex items-center gap-1.5">
            <Icon name="alt_route" className="text-base text-primary" />
            <span>数据流</span>
          </span>
          <span className="text-[11px] font-normal text-outline">
            {item.dataflow?.sanitized ? `已识别缓解${item.dataflow.sanitizer ? `：${item.dataflow.sanitizer}` : ""}` : item.dataflow ? (item.dataflow.reachable ? "标记为可达" : "未标记为可达") : "没有数据流记录"}
          </span>
        </div>
        <div className="relative overflow-hidden rounded-lg border border-outline-variant/30 bg-surface-container-low p-3.5">
          <div className="flow-sweep pointer-events-none absolute inset-y-0 left-0 w-24 bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
          {steps.length ? (
            <ol className="relative z-10 grid grid-cols-1 gap-3 md:grid-cols-3">
              {steps.map((step, index) => (
                <li key={`${item.candidate_id}-${index}`} className="rounded border border-outline-variant/30 bg-white p-2.5 shadow-sm">
                  <div className="mb-1 text-[11px] font-semibold text-primary">{index + 1}</div>
                  <div className="font-mono text-xs text-on-surface">{step}</div>
                </li>
              ))}
            </ol>
          ) : <p className="relative z-10 text-xs text-outline">这条结果没有逐步数据流。</p>}
        </div>
      </div>
      {item.semantic_explanation ? (
        <p className="mb-4 rounded-lg border border-outline-variant/30 bg-surface-container-low p-3.5 text-xs leading-relaxed text-on-surface">
          <span className="font-bold">语义说明：</span>{item.semantic_explanation}
        </p>
      ) : null}
      {item.exploitability_reason ? <p className="mb-4 text-xs leading-relaxed text-on-surface-variant"><span className="font-bold text-on-surface">可利用性：</span>{item.exploitability_reason}</p> : null}
      {item.rule_evidence.recommendation ? (
        <div className="flex items-start gap-3 rounded-lg border border-primary/30 bg-surface-container-highest/60 p-3.5">
          <Icon name="lightbulb" className="mt-0.5 shrink-0 text-[19px] text-primary" />
          <div className="text-xs leading-relaxed text-on-surface">
            <span className="font-bold text-primary">处置建议：</span>{item.rule_evidence.recommendation}
          </div>
        </div>
      ) : null}
    </article>
  );
}

function EvaluationCard({ task }: { task: EvaluationTask }) {
  const suiteRuns = task.metrics_json?.runs;
  const proposed = task.metrics_json?.proposed_agent;
  const skipped = task.metrics_json?.skipped ?? {};
  const failed = task.metrics_json?.failed ?? {};
  return (
    <div className="console-card flex flex-col gap-5 rounded-xl p-6">
      <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-container text-primary">
            <Icon name="insights" className="text-base" />
          </div>
          <div>
            <h3 className="font-headline text-base font-bold text-on-surface">评测指标</h3>
            <p className="max-w-md truncate font-mono text-xs text-outline">{task.manifest_path}</p>
          </div>
        </div>
        <StatusPill status={task.status} />
      </div>
      <div className="flex flex-col justify-between gap-3 rounded-lg border border-outline-variant/30 bg-surface-variant p-3.5 sm:flex-row sm:items-center">
        <div className="flex items-center gap-2">
          <Icon name="data_object" className="text-base text-outline" />
          <span className="font-mono text-xs font-semibold text-on-surface">{task.model_backend}</span>
        </div>
        <span className="font-mono text-[11px] text-outline" title={task.id}>{task.id.slice(0, 8)}</span>
      </div>
      {proposed ? <MetricGrid title="proposed_agent" metrics={proposed} /> : null}
      {suiteRuns ? Object.entries(suiteRuns).map(([name, run]) => <MetricGrid key={name} title={name} metrics={metricRecord(run)} />) : null}
      {!proposed && !suiteRuns ? <p className="text-sm text-on-surface-variant">{task.error || "等待评测结果。"}</p> : null}
      {Object.keys(skipped).length || Object.keys(failed).length ? (
        <div className="space-y-1 rounded-lg border border-outline-variant/40 bg-surface-variant p-3 text-xs text-on-surface-variant">
          {Object.entries(skipped).map(([name, reason]) => <p key={name}>{name} 已跳过：{reason}</p>)}
          {Object.entries(failed).map(([name, reason]) => <p key={name} className="text-error">{name} 失败：{reason}</p>)}
        </div>
      ) : null}
      <div className="overflow-hidden rounded-xl border border-outline-variant/40 bg-code-bg">
        <div className="flex items-center justify-between border-b border-outline-variant/15 bg-[#0b1218] px-4 py-2.5">
          <span className="font-mono text-xs text-outline-variant">{task.id.slice(0, 8)}.log</span>
          <span className="font-mono text-[11px] text-outline-variant">{task.model_backend}</span>
        </div>
        <div className="space-y-1.5 overflow-x-auto p-4 font-mono text-xs leading-relaxed text-code-text">
          {evaluationLog(task).map((line) => <div key={line}>{line}</div>)}
        </div>
      </div>
    </div>
  );
}

function MetricGrid({ title, metrics }: { title: string; metrics: Record<string, unknown> }) {
  const present = METRIC_KEYS.filter((key) => metrics[key] !== undefined && metrics[key] !== null);
  if (!present.length) return null;
  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-semibold text-on-surface">{title}</span>
        <span className="font-mono text-[11px] text-outline">{present.length} 项</span>
      </div>
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-4">
        {present.map((key) => (
          <div key={key} className="flex flex-col rounded-lg border border-outline-variant/30 bg-surface-container-low p-3">
            <span className="font-mono text-[11px] uppercase tracking-wider text-outline">{key}</span>
            <span className="mt-1 font-mono text-xl font-bold text-on-surface">{formatMetric(metrics[key])}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function pipelineFeet(scan?: ScanTask): string[] {
  const summary = scan?.summary_json;
  if (!summary) return ["等待任务", "等待任务", "等待任务", "等待任务", "等待任务", "等待任务", "等待任务"];
  const files = summaryNumber(summary, "files_scanned");
  const candidates = summaryNumber(summary, "candidate_count");
  const dfg = summaryNumber(summary, "dfg_edges");
  const review = summaryNumber(summary, "review_count");
  const confirmed = summaryNumber(summary, "confirmed_count");
  const parser = String(summary.parser_backend ?? "解析器");
  return [
    files === null ? parser : `${parser} · ${files} 文件`,
    candidates === null ? "无候选数" : `${candidates} 个候选`,
    dfg === null ? "无数据流统计" : `${dfg} 条边`,
    scan?.model_backend || "模型",
    summary.llm_semantics ? "DeepSeek" : "模板说明",
    review === null ? "无复核数" : `复核 ${review}`,
    confirmed === null ? "无确认数" : `确认 ${confirmed}`
  ];
}

function traceLines(scan?: ScanTask): string[] {
  if (!scan) return ["选择一条任务后，这里显示那次扫描写进摘要的数字。"];
  if (scan.status === "failed") return [scan.error || "扫描失败"];
  const summary = scan.summary_json;
  if (!summary) return [`任务状态 ${scan.status}，摘要尚未写入。`];
  const agents = Array.isArray(summary.executed_agents) ? summary.executed_agents.map(String).join(" → ") : "";
  const lines = [
    `文件 ${formatMetric(summary.files_scanned)}，函数 ${formatMetric(summary.functions_discovered)}，解析器 ${String(summary.parser_backend ?? "未知")}。`,
    `候选 ${formatMetric(summary.candidate_count)}，确认 ${formatMetric(summary.confirmed_count)}，复核 ${formatMetric(summary.review_count)}，过滤 ${formatMetric(summary.filtered_count)}。`,
    `数据流边 ${formatMetric(summary.dfg_edges)}，控制流节点 ${formatMetric(summary.cfg_nodes)}，模型 ${scan.model_backend}${summary.model_fallback ? "，已降级为 mock" : ""}。`
  ];
  if (agents) lines.push(agents);
  return lines;
}

function evaluationLog(task: EvaluationTask): string[] {
  const lines = [`清单 ${task.manifest_path}`, `后端 ${task.model_backend}`, `状态 ${task.status}`];
  if (task.error) lines.push(task.error);
  if (task.metrics_json?.proposed_agent) lines.push(`proposed_agent ${metricText(task.metrics_json.proposed_agent)}`);
  const runs = task.metrics_json?.runs;
  if (runs) {
    for (const [name, run] of Object.entries(runs)) lines.push(`${name} ${metricText(metricRecord(run))}`);
  }
  for (const [name, reason] of Object.entries(task.metrics_json?.skipped ?? {})) lines.push(`${name} 已跳过：${reason}`);
  for (const [name, reason] of Object.entries(task.metrics_json?.failed ?? {})) lines.push(`${name} 失败：${reason}`);
  if (lines.length === 3) lines.push("等待评测结果。");
  return lines;
}

function metricRecord(run: Record<string, unknown>): Record<string, unknown> {
  const nested = run.metrics;
  if (typeof nested === "object" && nested !== null) return nested as Record<string, unknown>;
  return run;
}

function metricText(metrics: Record<string, unknown>) {
  return METRIC_KEYS.filter((key) => metrics[key] !== undefined).map((key) => `${key}=${formatMetric(metrics[key])}`).join("  ");
}

function formatMetric(value: unknown) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return "—";
    if (Number.isInteger(value)) return String(value);
    return String(Math.round(value * 10000) / 10000);
  }
  if (value === undefined || value === null || value === "") return "—";
  return String(value);
}

function summaryNumber(summary: Record<string, unknown> | undefined, key: string): number | null {
  if (!summary || summary[key] === undefined || summary[key] === null) return null;
  const value = Number(summary[key]);
  return Number.isFinite(value) ? value : null;
}

function formatTime(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
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

function countDecisions(findings: Finding[]) {
  return findings.reduce(
    (sum, item) => {
      if (item.final_decision === "vulnerable") sum.vulnerable += 1;
      if (item.final_decision === "needs_review") sum.needs_review += 1;
      return sum;
    },
    { vulnerable: 0, needs_review: 0 }
  );
}

function decisionRank(decision: string) {
  return ({ needs_review: 0, vulnerable: 1, low_risk: 2, filtered_false_positive: 3 } as Record<string, number>)[decision] ?? 4;
}

function decisionLabel(decision: string) {
  return ({
    vulnerable: "确认漏洞",
    needs_review: "待复核",
    filtered_false_positive: "误报过滤",
    low_risk: "低风险"
  } as Record<string, string>)[decision] ?? decision;
}

function decisionTone(decision: string) {
  if (decision === "vulnerable") return "border-error/30 bg-red-100 text-error";
  if (decision === "needs_review") return "border-amber-300 bg-amber-100 text-status-amber";
  if (decision === "filtered_false_positive") return "border-outline-variant/40 bg-surface-container text-outline";
  return "border-emerald-300 bg-emerald-50 text-status-green";
}

function severityPill(severity: string) {
  const value = severity.toLowerCase();
  if (value === "critical") return "bg-error text-white";
  if (value === "high") return "bg-status-amber text-white";
  if (value === "medium") return "border border-amber-300 bg-amber-100 text-status-amber";
  return "border border-slate-300 bg-slate-100 text-slate-700";
}

function severityBadge(severity: string) {
  const value = severity.toLowerCase();
  if (value === "critical") return "border-[#FA746F]/40 bg-[#FDF2F2] text-[#A83836]";
  if (value === "high") return "border-amber-300 bg-amber-50 text-amber-700";
  if (value === "medium") return "border-amber-200 bg-amber-50/80 text-amber-800";
  return "border-slate-300 bg-slate-100 text-slate-700";
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

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
