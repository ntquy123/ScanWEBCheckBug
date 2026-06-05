import "dotenv/config";

function readNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function readBoolean(name: string, fallback = false): boolean {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  return ["1", "true", "yes", "on"].includes(raw.toLowerCase());
}

function readCorsOrigins(): string[] {
  const raw = process.env.CORS_ORIGIN ?? "http://localhost:5173";
  return raw
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: readNumber("PORT", 4000),
  redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
  corsOrigins: readCorsOrigins(),
  pythonBin:
    process.env.PYTHON_BIN ?? (process.platform === "win32" ? "python" : "python3"),
  scanTimeoutMs: readNumber("SCAN_TIMEOUT_MS", 30000),
  workerConcurrency: readNumber("WORKER_CONCURRENCY", 2),
  allowPrivateTargets: readBoolean("ALLOW_PRIVATE_TARGETS", false),
};

export function isOriginAllowed(origin?: string): boolean {
  if (!origin) {
    return true;
  }

  return env.corsOrigins.includes("*") || env.corsOrigins.includes(origin);
}
