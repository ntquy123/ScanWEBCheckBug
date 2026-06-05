export type ScanStatus = "queued" | "running" | "completed" | "failed";

export type CandidateCategory = "backend_language" | "framework" | "database";

export interface ScanJobData {
  url: string;
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
  statusCode: number;
  title?: string;
  server?: string;
  poweredBy?: string;
  contentType?: string;
}

export interface ScanResult {
  scannedAt: string;
  durationMs: number;
  http: ScanHttpInfo;
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

export interface ScanProgress {
  status: ScanStatus;
  stage: string;
  percent: number;
  message: string;
  result?: ScanResult;
  error?: string;
}
