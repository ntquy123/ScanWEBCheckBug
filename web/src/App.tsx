import {
  Activity,
  AlertTriangle,
  Database,
  LoaderCircle,
  Radar,
  Server,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000";

type ScanStatus = "queued" | "running" | "completed" | "failed";

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
    statusCode: number;
    title?: string;
    server?: string;
    poweredBy?: string;
    contentType?: string;
  };
  backendLanguages: FingerprintCandidate[];
  frameworks: FingerprintCandidate[];
  databases: FingerprintCandidate[];
  summary: {
    backendLanguage: string;
    backendConfidence: number;
    database: string;
    databaseConfidence: number;
  };
  notes: string[];
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
      }
    });

    socket.on("scan:completed", (payload: SocketPayload) => {
      if (payload.jobId !== activeJobRef.current) {
        return;
      }
      setProgress(payload.progress);
      setResult(payload.result ?? payload.progress.result ?? null);
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

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextUrl = targetUrl.trim();
    if (!nextUrl) {
      setError("Nhap URL can scan");
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
        body: JSON.stringify({ url: nextUrl }),
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

        {result ? (
          <section className="http-details">
            <h2>HTTP evidence</h2>
            <dl>
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
