import {
  Activity,
  AlertTriangle,
  Bug,
  Code2,
  Database,
  LoaderCircle,
  MonitorCog,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000";

type ScanStatus = "queued" | "running" | "completed" | "failed";
type ScanMethod = "GET" | "POST";
type ScanBodyType = "json" | "form";

interface Evidence {
  source: string;
  detail: string;
  value?: string;
}

interface FingerprintCandidate {
  name: string;
  category: string;
  confidence: number;
  evidence: Evidence[];
}

interface ScanResult {
  scannedAt: string;
  durationMs: number;
  http: {
    inputUrl: string;
    finalUrl: string;
    method: ScanMethod;
    bodyType?: ScanBodyType;
    statusCode: number;
    title?: string;
    server?: string;
    poweredBy?: string;
    contentType?: string;
  };
  serverFingerprint: {
    webServer: string;
    operatingSystem: string;
    confidence: number;
    evidence: Evidence[];
  };
  backendLanguages: FingerprintCandidate[];
  frameworks: FingerprintCandidate[];
  databases: FingerprintCandidate[];
  securityFindings: SecurityFinding[];
  summary: {
    backendLanguage: string;
    backendConfidence: number;
    database: string;
    databaseConfidence: number;
  };
  notes: string[];
}

interface SecurityFinding {
  title: string;
  severity: "info" | "low" | "medium" | "high";
  confidence: number;
  evidence: Evidence[];
  recommendation?: string;
}

interface ScanProgress {
  status: ScanStatus;
  stage: string;
  percent: number;
  message: string;
  result?: ScanResult;
  error?: string;
}

interface SocketPayload {
  jobId: string;
  progress: ScanProgress;
  result?: ScanResult;
}

const initialProgress: ScanProgress = {
  status: "queued",
  stage: "idle",
  percent: 0,
  message: "San sang",
};

export default function App() {
  const [targetUrl, setTargetUrl] = useState("");
  const [method, setMethod] = useState<ScanMethod>("GET");
  const [bodyType, setBodyType] = useState<ScanBodyType>("json");
  const [bodyJson, setBodyJson] = useState('{\n  "username": "test",\n  "password": "test"\n}');
  const [bodyForm, setBodyForm] = useState(
    "action=wp_manga_signin\nlogin=test@example.com\npass=test123\nrememberme=forever\nnonce=replace_with_nonce",
  );
  const [checkSqlInjection, setCheckSqlInjection] = useState(true);
  const [jobId, setJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState<ScanProgress>(initialProgress);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const socketRef = useRef<Socket | null>(null);
  const activeJobRef = useRef<string | null>(null);

  const isScanning = progress.status === "queued" || progress.status === "running" || isSubmitting;
  const backendSummary = result?.summary.backendLanguage ?? "Unknown";
  const databaseSummary = result?.summary.database ?? "Unknown";
  const progressPercent = Math.max(0, Math.min(progress.percent, 100));

  const statusText = useMemo(() => {
    if (error) {
      return "Failed";
    }
    if (result) {
      return "Completed";
    }
    return progress.status;
  }, [error, progress.status, result]);

  useEffect(() => {
    const socket = io(API_BASE_URL, {
      transports: ["websocket", "polling"],
    });
    socketRef.current = socket;

    socket.on("connect", () => {
      const currentJob = activeJobRef.current;
      if (currentJob) {
        socket.emit("scan:join", currentJob);
      }
    });

    socket.on("scan:progress", (payload: SocketPayload) => {
      if (payload.jobId !== activeJobRef.current) {
        return;
      }
      setProgress(payload.progress);
      if (payload.progress.result) {
        setResult(payload.progress.result);
      } else if (payload.progress.status === "completed") {
        void refreshJob(payload.jobId);
      }
    });

    socket.on("scan:completed", (payload: SocketPayload) => {
      if (payload.jobId !== activeJobRef.current) {
        return;
      }
      setProgress(payload.progress);
      const nextResult = payload.result ?? payload.progress.result;
      if (nextResult) {
        setResult(nextResult);
      } else {
        void refreshJob(payload.jobId);
      }
      setError(null);
    });

    socket.on("scan:failed", (payload: SocketPayload) => {
      if (payload.jobId !== activeJobRef.current) {
        return;
      }
      setProgress(payload.progress);
      setError(payload.progress.error ?? "Scan failed");
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(() => {
    if (!jobId || result || error) {
      return;
    }

    const refreshDelay = progress.status === "completed" ? 900 : 2200;
    const timer = window.setInterval(() => {
      void refreshJob(jobId);
    }, refreshDelay);

    return () => {
      window.clearInterval(timer);
    };
  }, [error, jobId, progress.status, result]);

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextUrl = targetUrl.trim();
    if (!nextUrl) {
      setError("Nhap URL can scan");
      return;
    }

    if (method === "POST" && bodyType === "json" && bodyJson.trim()) {
      try {
        JSON.parse(bodyJson);
      } catch {
        setError("Body JSON khong hop le");
        return;
      }
    }

    if (method === "POST" && bodyType === "form" && !bodyForm.trim()) {
      setError("Form Data khong duoc de trong");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setResult(null);
    setProgress({
      status: "queued",
      stage: "submit",
      percent: 0,
      message: "Dang tao scan job",
    });

    try {
      const response = await fetch(`${API_BASE_URL}/api/scans`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: nextUrl,
          method,
          ...(method === "POST" ? { bodyType } : {}),
          checkSqlInjection,
          ...(method === "POST" && bodyType === "json" && bodyJson.trim()
            ? { bodyJson: bodyJson.trim() }
            : {}),
          ...(method === "POST" && bodyType === "form" && bodyForm.trim()
            ? { bodyForm: bodyForm.trim() }
            : {}),
        }),
      });

      const payload = (await response.json()) as {
        jobId?: string;
        progress?: ScanProgress;
        error?: string;
      };

      if (!response.ok || !payload.jobId) {
        throw new Error(payload.error ?? "Khong tao duoc scan job");
      }

      activeJobRef.current = payload.jobId;
      setJobId(payload.jobId);
      if (payload.progress) {
        setProgress(payload.progress);
      }
      socketRef.current?.emit("scan:join", payload.jobId);
      void refreshJob(payload.jobId);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed");
      setProgress({
        status: "failed",
        stage: "failed",
        percent: 100,
        message: "Scan failed",
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function refreshJob(nextJobId: string) {
    const response = await fetch(`${API_BASE_URL}/api/scans/${nextJobId}`);
    if (!response.ok) {
      return;
    }

    if (nextJobId !== activeJobRef.current) {
      return;
    }

    const payload = (await response.json()) as {
      progress?: unknown;
      result?: ScanResult;
      failedReason?: string;
    };

    if (isScanProgress(payload.progress)) {
      setProgress(payload.progress);
    }
    if (payload.result) {
      setResult(payload.result);
    }
    if (payload.failedReason) {
      setError(payload.failedReason);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <ShieldCheck size={24} aria-hidden="true" />
          <span>ScanWEBCheckBug</span>
        </div>
        <div className="connection">
          <Wifi size={16} aria-hidden="true" />
          <span>API {API_BASE_URL.replace(/^https?:\/\//, "")}</span>
        </div>
      </header>

      <main className="workspace">
        <section className="scanner-surface">
          <form className="scan-form" onSubmit={startScan}>
            <label htmlFor="target-url">Target URL</label>
            <div className="input-row">
              <input
                id="target-url"
                value={targetUrl}
                onChange={(event) => setTargetUrl(event.target.value)}
                placeholder="https://example.com"
                spellCheck={false}
                autoComplete="url"
              />
              <button type="submit" disabled={isSubmitting} title="Start scan">
                {isSubmitting ? (
                  <LoaderCircle className="spin" size={18} aria-hidden="true" />
                ) : (
                  <Radar size={18} aria-hidden="true" />
                )}
                <span>Scan</span>
              </button>
            </div>
            <div className="advanced-controls">
              <div className="method-toggle" aria-label="HTTP method">
                <button
                  type="button"
                  className={method === "GET" ? "active" : ""}
                  onClick={() => setMethod("GET")}
                >
                  GET
                </button>
                <button
                  type="button"
                  className={method === "POST" ? "active" : ""}
                  onClick={() => setMethod("POST")}
                >
                  POST
                </button>
              </div>
              <label className="check-toggle">
                <input
                  type="checkbox"
                  checked={checkSqlInjection}
                  onChange={(event) => setCheckSqlInjection(event.target.checked)}
                />
                <Bug size={16} aria-hidden="true" />
                <span>SQLi probe</span>
              </label>
            </div>
            {method === "POST" ? (
              <div className="body-editor">
                <div className="body-editor-head">
                  <label htmlFor={bodyType === "json" ? "body-json" : "body-form"}>
                    {bodyType === "json" ? "Body JSON" : "Form Data"}
                  </label>
                  <div className="body-type-toggle" aria-label="POST body type">
                    <button
                      type="button"
                      className={bodyType === "json" ? "active" : ""}
                      onClick={() => setBodyType("json")}
                    >
                      JSON
                    </button>
                    <button
                      type="button"
                      className={bodyType === "form" ? "active" : ""}
                      onClick={() => setBodyType("form")}
                    >
                      Form
                    </button>
                  </div>
                </div>
                {bodyType === "json" ? (
                  <textarea
                    id="body-json"
                    value={bodyJson}
                    onChange={(event) => setBodyJson(event.target.value)}
                    spellCheck={false}
                  />
                ) : (
                  <textarea
                    id="body-form"
                    value={bodyForm}
                    onChange={(event) => setBodyForm(event.target.value)}
                    spellCheck={false}
                  />
                )}
              </div>
            ) : null}
          </form>

          <div className="progress-area" aria-live="polite">
            <div className="progress-copy">
              <span>{statusText}</span>
              <strong>{progress.message}</strong>
            </div>
            <div className="progress-track">
              <div className="progress-bar" style={{ width: `${progressPercent}%` }} />
            </div>
            <div className="job-meta">
              <span>Stage: {progress.stage}</span>
              <span>{progressPercent}%</span>
              {jobId ? <span>Job: {jobId}</span> : null}
            </div>
          </div>

          {error ? (
            <div className="error-line">
              <AlertTriangle size={18} aria-hidden="true" />
              <span>{error}</span>
            </div>
          ) : null}
        </section>

        <section className="summary-grid">
          <MetricCard
            icon={Server}
            label="Backend language"
            value={backendSummary}
            confidence={result?.summary.backendConfidence ?? 0}
          />
          <MetricCard
            icon={Database}
            label="Database"
            value={databaseSummary}
            confidence={result?.summary.databaseConfidence ?? 0}
          />
          <MetricCard
            icon={Server}
            label="Web server"
            value={result?.serverFingerprint?.webServer ?? "Unknown"}
            confidence={result?.serverFingerprint?.confidence ?? 0}
          />
          <MetricCard
            icon={MonitorCog}
            label="OS guess"
            value={result?.serverFingerprint?.operatingSystem ?? "Unknown"}
            confidence={result?.serverFingerprint?.confidence ?? 0}
          />
          <MetricCard
            icon={Activity}
            label="HTTP status"
            value={result ? String(result.http.statusCode) : "-"}
            {...(result?.http.finalUrl ? { detail: result.http.finalUrl } : {})}
          />
        </section>

        <section className="result-grid">
          <CandidatePanel icon={Server} title="Backend language" candidates={result?.backendLanguages ?? []} />
          <CandidatePanel icon={Activity} title="Framework / CMS" candidates={result?.frameworks ?? []} />
          <CandidatePanel icon={Database} title="Database" candidates={result?.databases ?? []} />
        </section>

        {result ? <FindingsPanel findings={result.securityFindings ?? []} /> : null}

        {result ? (
          <section className="http-details">
            <h2>HTTP evidence</h2>
            <dl>
              <div>
                <dt>Method</dt>
                <dd>
                  {result.http.method ?? "-"}
                  {result.http.bodyType ? ` / ${result.http.bodyType}` : ""}
                </dd>
              </div>
              <div>
                <dt>Final URL</dt>
                <dd>{result.http.finalUrl}</dd>
              </div>
              <div>
                <dt>Title</dt>
                <dd>{result.http.title ?? "-"}</dd>
              </div>
              <div>
                <dt>Server</dt>
                <dd>{result.http.server ?? "-"}</dd>
              </div>
              <div>
                <dt>X-Powered-By</dt>
                <dd>{result.http.poweredBy ?? "-"}</dd>
              </div>
              <div>
                <dt>Duration</dt>
                <dd>{result.durationMs}ms</dd>
              </div>
            </dl>
          </section>
        ) : null}
      </main>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  confidence,
  detail,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  confidence?: number;
  detail?: string;
}) {
  return (
    <article className="metric-card">
      <Icon size={22} aria-hidden="true" />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        {typeof confidence === "number" ? <small>{formatConfidence(confidence)}</small> : null}
        {detail ? <small title={detail}>{detail}</small> : null}
      </div>
    </article>
  );
}

function CandidatePanel({
  icon: Icon,
  title,
  candidates,
}: {
  icon: LucideIcon;
  title: string;
  candidates: FingerprintCandidate[];
}) {
  return (
    <article className="result-panel">
      <div className="panel-title">
        <Icon size={20} aria-hidden="true" />
        <h2>{title}</h2>
      </div>

      {candidates.length === 0 ? (
        <p className="empty-state">No public fingerprint found.</p>
      ) : (
        <div className="candidate-list">
          {candidates.map((candidate) => (
            <div className="candidate" key={`${candidate.category}:${candidate.name}`}>
              <div className="candidate-head">
                <strong>{candidate.name}</strong>
                <span className={`confidence ${confidenceBand(candidate.confidence)}`}>
                  {formatConfidence(candidate.confidence)}
                </span>
              </div>
              <ul>
                {candidate.evidence.map((item, index) => (
                  <li key={`${item.source}:${index}`}>
                    <span>{item.source}</span>
                    <p>{item.detail}</p>
                    {item.value ? <code>{item.value}</code> : null}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

function FindingsPanel({ findings }: { findings: SecurityFinding[] }) {
  return (
    <section className="findings-panel">
      <div className="panel-title">
        <ShieldAlert size={20} aria-hidden="true" />
        <h2>Security findings</h2>
      </div>

      {findings.length === 0 ? (
        <p className="empty-state">No finding from this response.</p>
      ) : (
        <div className="finding-list">
          {findings.map((finding) => (
            <article className="finding" key={`${finding.title}:${finding.severity}`}>
              <div className="finding-head">
                <strong>{finding.title}</strong>
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
              </div>
              <small>{formatConfidence(finding.confidence)}</small>
              <ul>
                {finding.evidence.map((item, index) => (
                  <li key={`${item.source}:${index}`}>
                    <span>{item.source}</span>
                    <p>{item.detail}</p>
                    {item.value ? <code>{item.value}</code> : null}
                  </li>
                ))}
              </ul>
              {finding.recommendation ? (
                <p className="recommendation">
                  <Code2 size={15} aria-hidden="true" />
                  <span>{finding.recommendation}</span>
                </p>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function isScanProgress(value: unknown): value is ScanProgress {
  if (!value || typeof value !== "object") {
    return false;
  }

  const maybe = value as Partial<ScanProgress>;
  return typeof maybe.stage === "string" && typeof maybe.percent === "number";
}

function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}% confidence`;
}

function confidenceBand(confidence: number): "high" | "medium" | "low" {
  if (confidence >= 0.75) {
    return "high";
  }
  if (confidence >= 0.45) {
    return "medium";
  }
  return "low";
}
