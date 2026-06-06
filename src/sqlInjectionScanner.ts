import type {
  Evidence,
  ExposureScanHints,
  FindingSeverity,
  ScanBodyType,
  ScanMethod,
  SqlInjectionFinding,
  SqlInjectionScanRequest,
  SqlInjectionScanResult,
  SqlInjectionScenario,
} from "./types.js";

interface MutableTarget {
  label: string;
  originalValue: string;
  mutate(nextValue: string): HttpSpec;
}

interface HttpSpec {
  url: string;
  method: ScanMethod;
  bodyType?: ScanBodyType;
  bodyJson?: string;
  bodyForm?: string;
}

interface FetchSample {
  statusCode: number;
  contentType?: string;
  body: string;
  bodyLength: number;
  durationMs: number;
}

type Dbms = "MySQL / MariaDB" | "PostgreSQL" | "Microsoft SQL Server" | "SQLite";

const MAX_BODY_BYTES = 48 * 1024;
const MAX_MUTATION_TARGETS = 4;
const MAX_TIME_TARGETS = 3;
const TIME_DELAY_SECONDS = 3;
const BASE_TIMEOUT_MS = 6500;
const TIME_TIMEOUT_MS = 8500;
const USER_AGENT = "ScanWEBCheckBug/1.3 safe-sqli-check";

const SQL_ERROR_PATTERNS: Array<[Dbms, RegExp, string]> = [
  [
    "MySQL / MariaDB",
    /(you have an error in your sql syntax|mysql_fetch|mysqli_|mariadb server version|mysql server version|sql syntax.*mysql)/i,
    "MySQL/MariaDB error text exposed",
  ],
  [
    "PostgreSQL",
    /(postgresql|pg_query|org\.postgresql|npgsql|psycopg2|pq: syntax error|unterminated quoted string)/i,
    "PostgreSQL error text exposed",
  ],
  [
    "Microsoft SQL Server",
    /(microsoft sql server|sql server|odbc sql server|sqlsrv|system\.data\.sqlclient|unclosed quotation mark|incorrect syntax near)/i,
    "Microsoft SQL Server error text exposed",
  ],
  ["SQLite", /(sqlite|sqlite3|sql error|near ".+": syntax error)/i, "SQLite error text exposed"],
];

export async function runSqlInjectionScan(request: SqlInjectionScanRequest): Promise<SqlInjectionScanResult> {
  const startedAt = Date.now();
  const spec = normalizeSpec(request);
  const targets = buildMutableTargets(spec).slice(0, MAX_MUTATION_TARGETS);
  const inferredDbms = inferDbms(request.hints ?? {});
  const findings: SqlInjectionFinding[] = [];
  let checkedCount = 0;

  if (!targets.length) {
    return buildResult(startedAt, request.scenario, 0, inferredDbms, findings, [
      "No mutable query, JSON, or form fields were available for SQL injection probing.",
    ]);
  }

  const baseline = await fetchSample(spec, BASE_TIMEOUT_MS);

  if (request.scenario === "inband") {
    for (const target of targets) {
      checkedCount += await runInbandTarget(target, baseline, findings);
    }
  } else {
    for (const target of targets.slice(0, MAX_TIME_TARGETS)) {
      checkedCount += await runTimeTarget(target, baseline, inferredDbms, findings);
    }
  }

  return buildResult(startedAt, request.scenario, checkedCount, inferredDbms, findings, [
    "Safe SQLi check uses limited probes only and does not extract database data.",
    "In-band checks look for SQL error text and boolean response differences.",
    "Time-based checks use short database-specific delay probes and compare response timing.",
  ]);
}

function buildResult(
  startedAt: number,
  scenario: SqlInjectionScenario,
  checkedCount: number,
  inferredDbms: string[],
  findings: SqlInjectionFinding[],
  extraNotes: string[],
): SqlInjectionScanResult {
  findings.sort((left, right) => {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    return severityOrder[left.severity] - severityOrder[right.severity] || right.confidence - left.confidence;
  });

  return {
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    scenario,
    checkedCount,
    foundCount: findings.length,
    inferredDbms,
    findings,
    notes: extraNotes,
  };
}

function normalizeSpec(request: SqlInjectionScanRequest): HttpSpec {
  return {
    url: normalizeTargetUrl(request.url),
    method: request.method,
    ...(request.method === "POST" ? { bodyType: request.bodyType ?? "json" } : {}),
    ...(request.method === "POST" && request.bodyType === "json" && request.bodyJson ? { bodyJson: request.bodyJson } : {}),
    ...(request.method === "POST" && request.bodyType === "form" && request.bodyForm ? { bodyForm: request.bodyForm } : {}),
  };
}

function normalizeTargetUrl(input: string): string {
  const url = new URL(input);
  url.hash = "";
  return url.toString();
}

async function runInbandTarget(
  target: MutableTarget,
  baseline: FetchSample,
  findings: SqlInjectionFinding[],
): Promise<number> {
  let checked = 0;

  const errorProbe = await fetchSample(target.mutate(buildQuoteProbe(target.originalValue)), BASE_TIMEOUT_MS);
  checked += 1;
  const sqlError = detectSqlError(errorProbe.body);
  if (sqlError) {
    findings.push(
      buildFinding({
        scenario: "inband",
        target: target.label,
        dbms: sqlError.dbms,
        severity: "high",
        confidence: 0.86,
        description: "Quote probe caused public SQL error text in the response",
        evidence: [
          metricEvidence("baseline", baseline),
          metricEvidence("probe", errorProbe),
          {
            source: "body:error",
            detail: sqlError.detail,
            value: surroundingText(errorProbe.body, sqlError.index),
          },
        ],
      }),
    );
    return checked;
  }

  const trueProbe = await fetchSample(target.mutate(buildBooleanProbe(target.originalValue, true)), BASE_TIMEOUT_MS);
  const falseProbe = await fetchSample(target.mutate(buildBooleanProbe(target.originalValue, false)), BASE_TIMEOUT_MS);
  checked += 2;

  const trueSimilarity = responseSimilarity(baseline, trueProbe);
  const falseSimilarity = responseSimilarity(baseline, falseProbe);
  const pairSimilarity = responseSimilarity(trueProbe, falseProbe);

  if (trueSimilarity >= 0.72 && falseSimilarity <= 0.55 && pairSimilarity <= 0.55) {
    findings.push(
      buildFinding({
        scenario: "inband",
        target: target.label,
        dbms: "Unknown SQL database",
        severity: "medium",
        confidence: 0.62,
        description: "Boolean SQL predicate changed the response shape",
        evidence: [
          metricEvidence("baseline", baseline),
          metricEvidence("true-predicate", trueProbe),
          metricEvidence("false-predicate", falseProbe),
          {
            source: "response:diff",
            detail: "True predicate stayed close to baseline while false predicate differed",
            value: `baseline/true=${trueSimilarity.toFixed(2)}, baseline/false=${falseSimilarity.toFixed(
              2,
            )}, true/false=${pairSimilarity.toFixed(2)}`,
          },
        ],
      }),
    );
  }

  return checked;
}

async function runTimeTarget(
  target: MutableTarget,
  baseline: FetchSample,
  dbmsCandidates: string[],
  findings: SqlInjectionFinding[],
): Promise<number> {
  let checked = 0;
  const candidates = dbmsCandidates.filter((dbms): dbms is Dbms => isSupportedTimeDbms(dbms));

  for (const dbms of candidates.slice(0, 3)) {
    const payload = buildTimeProbe(target.originalValue, dbms);
    if (!payload) {
      continue;
    }

    const probe = await fetchSample(target.mutate(payload), TIME_TIMEOUT_MS);
    checked += 1;

    const delta = probe.durationMs - baseline.durationMs;
    if (probe.durationMs >= TIME_DELAY_SECONDS * 1000 - 350 && delta >= TIME_DELAY_SECONDS * 1000 - 700) {
      findings.push(
        buildFinding({
          scenario: "time",
          target: target.label,
          dbms,
          severity: "high",
          confidence: 0.78,
          description: "Database-specific delay probe changed response timing",
          evidence: [
            metricEvidence("baseline", baseline),
            metricEvidence("time-probe", probe),
            {
              source: "timing:delta",
              detail: "Probe response exceeded baseline by the expected delay window",
              value: `${delta}ms delta using ${dbms} delay syntax`,
            },
          ],
        }),
      );
      break;
    }
  }

  return checked;
}

function buildFinding(input: {
  scenario: SqlInjectionScenario;
  target: string;
  dbms: string;
  severity: FindingSeverity;
  confidence: number;
  description: string;
  evidence: Evidence[];
}): SqlInjectionFinding {
  return {
    ...input,
    recommendation:
      "Use parameterized queries/prepared statements, validate input server-side, and keep detailed SQL errors out of public responses.",
  };
}

function buildMutableTargets(spec: HttpSpec): MutableTarget[] {
  if (spec.method === "GET") {
    return buildGetTargets(spec);
  }
  if (spec.bodyType === "form") {
    return buildFormTargets(spec);
  }
  return buildJsonTargets(spec);
}

function buildGetTargets(spec: HttpSpec): MutableTarget[] {
  const url = new URL(spec.url);
  const pairs = Array.from(url.searchParams.entries());
  return pairs.map(([key, value], index) => ({
    label: `query parameter '${key}'`,
    originalValue: value,
    mutate(nextValue: string) {
      const nextUrl = new URL(spec.url);
      const nextPairs = Array.from(nextUrl.searchParams.entries());
      nextUrl.search = "";
      nextPairs.forEach(([pairKey, pairValue], pairIndex) => {
        nextUrl.searchParams.append(pairKey, pairIndex === index ? nextValue : pairValue);
      });
      return { ...spec, url: nextUrl.toString() };
    },
  }));
}

function buildFormTargets(spec: HttpSpec): MutableTarget[] {
  const pairs = parseFormText(spec.bodyForm ?? "");
  return pairs.map(([key, value], index) => ({
    label: `form field '${key}'`,
    originalValue: value,
    mutate(nextValue: string) {
      const mutated = pairs.map(([pairKey, pairValue], pairIndex) => [
        pairKey,
        pairIndex === index ? nextValue : pairValue,
      ] satisfies [string, string]);
      return { ...spec, bodyForm: formatFormText(mutated) };
    },
  }));
}

function buildJsonTargets(spec: HttpSpec): MutableTarget[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(spec.bodyJson || "{}");
  } catch {
    return [];
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return [];
  }

  return Object.entries(parsed)
    .filter(([, value]) => isScalar(value))
    .map(([key, value]) => ({
      label: `JSON field '${key}'`,
      originalValue: stringifyScalar(value),
      mutate(nextValue: string) {
        return {
          ...spec,
          bodyJson: JSON.stringify({
            ...(parsed as Record<string, unknown>),
            [key]: nextValue,
          }),
        };
      },
    }));
}

async function fetchSample(spec: HttpSpec, timeoutMs: number): Promise<FetchSample> {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const requestBody = buildBody(spec);
    const response = await fetch(spec.url, {
      method: spec.method,
      redirect: "manual",
      signal: controller.signal,
      headers: buildHeaders(spec),
      ...(requestBody !== undefined ? { body: requestBody } : {}),
    });
    const body = await readLimitedBody(response, MAX_BODY_BYTES);
    const contentType = response.headers.get("content-type") ?? undefined;

    return {
      statusCode: response.status,
      ...(contentType ? { contentType } : {}),
      body,
      bodyLength: body.length,
      durationMs: Date.now() - started,
    };
  } catch {
    return {
      statusCode: 0,
      body: "",
      bodyLength: 0,
      durationMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function buildHeaders(spec: HttpSpec): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "text/html,application/json,text/plain,*/*;q=0.3",
    "User-Agent": USER_AGENT,
  };

  if (spec.method === "POST" && spec.bodyType === "form") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (spec.method === "POST") {
    headers["Content-Type"] = "application/json";
  }

  return headers;
}

function buildBody(spec: HttpSpec): BodyInit | undefined {
  if (spec.method !== "POST") {
    return undefined;
  }
  if (spec.bodyType === "form") {
    return new URLSearchParams(parseFormText(spec.bodyForm ?? "")).toString();
  }
  return spec.bodyJson || "{}";
}

async function readLimitedBody(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return "";
  }

  const chunks: Buffer[] = [];
  let total = 0;

  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done || !value) {
      break;
    }

    const chunk = Buffer.from(value);
    const remaining = maxBytes - total;
    chunks.push(chunk.subarray(0, remaining));
    total += Math.min(chunk.length, remaining);

    if (chunk.length >= remaining) {
      await reader.cancel().catch(() => undefined);
      break;
    }
  }

  return Buffer.concat(chunks, total).toString("utf8");
}

function buildQuoteProbe(value: string): string {
  return `${value}'`;
}

function buildBooleanProbe(value: string, expectedTrue: boolean): string {
  if (isNumericLike(value)) {
    return `${value} AND 1=${expectedTrue ? "1" : "2"}`;
  }
  return `${value}' AND '${expectedTrue ? "1" : "2"}'='1`;
}

function buildTimeProbe(value: string, dbms: Dbms): string | null {
  const delay = TIME_DELAY_SECONDS;
  const numeric = isNumericLike(value);

  if (dbms === "MySQL / MariaDB") {
    return numeric ? `${value} AND SLEEP(${delay})` : `${value}' AND SLEEP(${delay}) AND '1'='1`;
  }

  if (dbms === "PostgreSQL") {
    return numeric
      ? `${value} AND 1=(SELECT 1 FROM pg_sleep(${delay}))`
      : `${value}' AND 1=(SELECT 1 FROM pg_sleep(${delay})) AND '1'='1`;
  }

  if (dbms === "Microsoft SQL Server") {
    return numeric ? `${value}; WAITFOR DELAY '0:0:${delay}'--` : `${value}'; WAITFOR DELAY '0:0:${delay}'--`;
  }

  return null;
}

function inferDbms(hints: ExposureScanHints): string[] {
  const text = [
    ...(hints.backendLanguages ?? []),
    ...(hints.frameworks ?? []),
    ...(hints.databases ?? []),
    hints.webServer ?? "",
    hints.operatingSystem ?? "",
  ]
    .join(" ")
    .toLowerCase();
  const dbms: Dbms[] = [];

  if (/mysql|mariadb|wordpress|php/.test(text)) {
    dbms.push("MySQL / MariaDB");
  }
  if (/postgres|postgresql|pg\b/.test(text)) {
    dbms.push("PostgreSQL");
  }
  if (/sql server|mssql|sqlserver|asp\.net/.test(text)) {
    dbms.push("Microsoft SQL Server");
  }
  if (/sqlite/.test(text)) {
    dbms.push("SQLite");
  }
  if (/node|express|fastify|nestjs|next\.js|nextjs/.test(text)) {
    dbms.push("PostgreSQL", "MySQL / MariaDB", "Microsoft SQL Server");
  }

  const unique = Array.from(new Set(dbms));
  return unique.length ? unique : ["MySQL / MariaDB", "PostgreSQL", "Microsoft SQL Server"];
}

function isSupportedTimeDbms(dbms: string): dbms is Dbms {
  return dbms === "MySQL / MariaDB" || dbms === "PostgreSQL" || dbms === "Microsoft SQL Server";
}

function detectSqlError(text: string): { dbms: Dbms; detail: string; index: number } | null {
  for (const [dbms, pattern, detail] of SQL_ERROR_PATTERNS) {
    const match = pattern.exec(text);
    if (match?.index !== undefined) {
      return { dbms, detail, index: match.index };
    }
  }
  return null;
}

function responseSimilarity(left: FetchSample, right: FetchSample): number {
  if (left.statusCode !== right.statusCode) {
    return 0;
  }
  const leftText = normalizeBody(left.body);
  const rightText = normalizeBody(right.body);
  if (!leftText && !rightText) {
    return 1;
  }
  if (!leftText || !rightText) {
    return 0;
  }

  const lengthScore = 1 - Math.min(Math.abs(leftText.length - rightText.length) / Math.max(leftText.length, rightText.length), 1);
  const prefixScore = commonPrefixRatio(leftText, rightText);
  return Number(((lengthScore * 0.65) + (prefixScore * 0.35)).toFixed(3));
}

function commonPrefixRatio(left: string, right: string): number {
  const limit = Math.min(left.length, right.length, 4000);
  let same = 0;
  for (let index = 0; index < limit; index += 1) {
    if (left[index] !== right[index]) {
      break;
    }
    same += 1;
  }
  return same / Math.max(limit, 1);
}

function normalizeBody(body: string): string {
  return body
    .replace(/[a-f0-9]{24,}/gi, "[hex]")
    .replace(/\d{10,}/g, "[num]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 12000);
}

function metricEvidence(source: string, sample: FetchSample): Evidence {
  return {
    source,
    detail: "HTTP response metrics",
    value: `status=${sample.statusCode}, bytes=${sample.bodyLength}, duration=${sample.durationMs}ms`,
  };
}

function surroundingText(text: string, index: number): string {
  return text
    .slice(Math.max(0, index - 120), index + 220)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 320);
}

function parseFormText(bodyForm: string): Array<[string, string]> {
  const raw = bodyForm.trim();
  if (!raw) {
    return [];
  }

  if (!raw.includes("\n") && raw.includes("=")) {
    return Array.from(new URLSearchParams(raw).entries()).filter(([key]) => Boolean(key));
  }

  const pairs: Array<[string, string]> = [];
  for (const line of raw.split(/\r?\n/)) {
    const stripped = line.trim();
    if (!stripped || stripped.startsWith("#")) {
      continue;
    }
    if (stripped.includes("=")) {
      const [key, ...rest] = stripped.split("=");
      if (key?.trim()) {
        pairs.push([key.trim(), rest.join("=").trim()]);
      }
      continue;
    }
    const [key, ...rest] = stripped.split(/\s+/);
    if (key) {
      pairs.push([key, rest.join(" ")]);
    }
  }
  return pairs;
}

function formatFormText(pairs: Array<[string, string]>): string {
  return pairs.map(([key, value]) => `${key}=${value}`).join("\n");
}

function isScalar(value: unknown): boolean {
  return value === null || ["string", "number", "boolean"].includes(typeof value);
}

function stringifyScalar(value: unknown): string {
  return value === null || value === undefined ? "" : String(value);
}

function isNumericLike(value: string): boolean {
  return /^-?\d+(?:\.\d+)?$/.test(value.trim());
}
