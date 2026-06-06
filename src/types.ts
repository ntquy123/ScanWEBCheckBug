export type ScanStatus = "queued" | "running" | "completed" | "failed";

export type CandidateCategory = "backend_language" | "framework" | "database";

export type ScanMethod = "GET" | "POST";
export type ScanBodyType = "json" | "form";

export interface ScanJobData {
  url: string;
  method: ScanMethod;
  bodyType?: ScanBodyType;
  bodyJson?: string;
  bodyForm?: string;
  checkSqlInjection: boolean;
  requestedAt: string;
}

export interface Evidence {
  source: string;
  detail: string;
  value?: string;
}

export interface FingerprintCandidate {
  name: string;
  category: CandidateCategory;
  confidence: number;
  evidence: Evidence[];
}

export interface ScanHttpInfo {
  inputUrl: string;
  finalUrl: string;
  method: ScanMethod;
  bodyType?: ScanBodyType;
  statusCode: number;
  title?: string;
  server?: string;
  poweredBy?: string;
  contentType?: string;
}

export interface ServerFingerprint {
  webServer: string;
  operatingSystem: string;
  confidence: number;
  evidence: Evidence[];
}

export type FindingSeverity = "info" | "low" | "medium" | "high";

export interface SecurityFinding {
  title: string;
  severity: FindingSeverity;
  confidence: number;
  evidence: Evidence[];
  recommendation?: string;
}

export interface ScanResult {
  scannedAt: string;
  durationMs: number;
  http: ScanHttpInfo;
  serverFingerprint: ServerFingerprint;
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

export interface ScanProgress {
  status: ScanStatus;
  stage: string;
  percent: number;
  message: string;
  result?: ScanResult;
  error?: string;
}

export type ExposureCategory =
  | "environment"
  | "secret"
  | "docker"
  | "vcs"
  | "node"
  | "php"
  | "wordpress"
  | "backup"
  | "server"
  | "log"
  | "directory";

export interface ExposureScanHints {
  backendLanguages?: string[];
  frameworks?: string[];
  databases?: string[];
  webServer?: string;
  operatingSystem?: string;
}

export interface ExposureFinding {
  path: string;
  url: string;
  category: ExposureCategory;
  severity: FindingSeverity;
  statusCode: number;
  contentType?: string;
  bytesRead: number;
  confidence: number;
  description: string;
  evidence: Evidence[];
}

export interface ExposureScanResult {
  scannedAt: string;
  durationMs: number;
  baseUrl: string;
  checkedCount: number;
  foundCount: number;
  profile: ExposureScanHints;
  findings: ExposureFinding[];
  notes: string[];
}
