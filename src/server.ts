import cors from "cors";
import express from "express";
import helmet from "helmet";
import { createServer } from "node:http";
import { Server as SocketServer } from "socket.io";
import { z } from "zod";

import { env, isOriginAllowed } from "./config.js";
import { runExposureScan } from "./exposureScanner.js";
import { createScanQueue, createScanQueueEvents } from "./queue.js";
import { runSqlInjectionScan } from "./sqlInjectionScanner.js";
import type { ExposureScanHints, ScanBodyType, ScanProgress, ScanResult, SqlInjectionScanRequest } from "./types.js";

const app = express();
const httpServer = createServer(app);
const scanQueue = createScanQueue();
const queueEvents = createScanQueueEvents();

const corsOptions: cors.CorsOptions = {
  origin(origin, callback) {
    callback(null, isOriginAllowed(origin));
  },
};

const io = new SocketServer(httpServer, {
  cors: corsOptions,
});

const scanRequestSchema = z
  .object({
    url: z.string().trim().min(3).max(2048),
    method: z.enum(["GET", "POST"]).default("GET"),
    bodyType: z.enum(["json", "form"]).default("json"),
    bodyJson: z.string().max(32768).optional(),
    bodyForm: z.string().max(32768).optional(),
    checkSqlInjection: z.boolean().default(true),
  })
  .superRefine((data, ctx) => {
    if (data.method === "POST" && data.bodyType === "json" && data.bodyJson?.trim()) {
      try {
        JSON.parse(data.bodyJson);
      } catch {
        ctx.addIssue({
          code: "custom",
          path: ["bodyJson"],
          message: "Body JSON khong hop le",
        });
      }
    }

    if (data.method === "POST" && data.bodyType === "form" && !data.bodyForm?.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["bodyForm"],
        message: "Form Data khong duoc de trong",
      });
    }
  });

const exposureScanSchema = z.object({
  url: z.string().trim().min(3).max(2048),
  hints: z
    .object({
      backendLanguages: z.array(z.string().trim().min(1).max(80)).max(12).optional(),
      frameworks: z.array(z.string().trim().min(1).max(80)).max(12).optional(),
      databases: z.array(z.string().trim().min(1).max(80)).max(12).optional(),
      webServer: z.string().trim().max(120).optional(),
      operatingSystem: z.string().trim().max(120).optional(),
    })
    .optional(),
});

const sqlInjectionScanSchema = z
  .object({
    url: z.string().trim().min(3).max(2048),
    method: z.enum(["GET", "POST"]).default("GET"),
    bodyType: z.enum(["json", "form"]).default("json"),
    bodyJson: z.string().max(32768).optional(),
    bodyForm: z.string().max(32768).optional(),
    scenario: z.enum(["inband", "time"]),
    hints: exposureScanSchema.shape.hints,
  })
  .superRefine((data, ctx) => {
    if (data.method === "POST" && data.bodyType === "json" && data.bodyJson?.trim()) {
      try {
        JSON.parse(data.bodyJson);
      } catch {
        ctx.addIssue({
          code: "custom",
          path: ["bodyJson"],
          message: "Body JSON khong hop le",
        });
      }
    }

    if (data.method === "POST" && data.bodyType === "form" && !data.bodyForm?.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["bodyForm"],
        message: "Form Data khong duoc de trong",
      });
    }
  });

app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json({ limit: "128kb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    queue: "ready",
  });
});

app.post("/api/scans", async (req, res) => {
  const parsed = scanRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: "URL khong hop le",
      issues: parsed.error.issues,
    });
    return;
  }

  const normalizedUrl = normalizeTargetUrl(parsed.data.url);
  if (!normalizedUrl) {
    res.status(400).json({
      error: "Chi ho tro URL http hoac https",
    });
    return;
  }

  const job = await scanQueue.add("fingerprint", {
    url: normalizedUrl,
    method: parsed.data.method,
    ...(parsed.data.method === "POST" ? { bodyType: parsed.data.bodyType } : {}),
    ...(parsed.data.method === "POST" && parsed.data.bodyType === "json" && parsed.data.bodyJson?.trim()
      ? { bodyJson: parsed.data.bodyJson.trim() }
      : {}),
    ...(parsed.data.method === "POST" && parsed.data.bodyType === "form" && parsed.data.bodyForm?.trim()
      ? { bodyForm: parsed.data.bodyForm.trim() }
      : {}),
    checkSqlInjection: parsed.data.checkSqlInjection,
    requestedAt: new Date().toISOString(),
  });

  const progress: ScanProgress = {
    status: "queued",
    stage: "queued",
    percent: 0,
    message: "Da dua vao hang doi scan",
  };
  await job.updateProgress(progress);

  res.status(202).json({
    jobId: job.id,
    status: progress.status,
    progress,
  });
});

app.get("/api/scans/:jobId", async (req, res) => {
  const job = await scanQueue.getJob(req.params.jobId);
  if (!job) {
    res.status(404).json({ error: "Khong tim thay scan job" });
    return;
  }

  const state = await job.getState();
  res.json({
    jobId: job.id,
    status: state,
    progress: job.progress,
    result: job.returnvalue,
    failedReason: job.failedReason,
  });
});

app.post("/api/exposure-scans", async (req, res) => {
  const parsed = exposureScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: "Yeu cau scan file public khong hop le",
      issues: parsed.error.issues,
    });
    return;
  }

  const normalizedUrl = normalizeTargetUrl(parsed.data.url);
  if (!normalizedUrl) {
    res.status(400).json({
      error: "Chi ho tro URL http hoac https",
    });
    return;
  }

  try {
    const result = await runExposureScan(normalizedUrl, normalizeExposureHints(parsed.data.hints));
    res.json(result);
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : "Exposure scan failed",
    });
  }
});

app.post("/api/sql-injection-scans", async (req, res) => {
  const parsed = sqlInjectionScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: "Yeu cau SQL injection scan khong hop le",
      issues: parsed.error.issues,
    });
    return;
  }

  const normalizedUrl = normalizeTargetUrl(parsed.data.url);
  if (!normalizedUrl) {
    res.status(400).json({
      error: "Chi ho tro URL http hoac https",
    });
    return;
  }

  try {
    const result = await runSqlInjectionScan({
      url: normalizedUrl,
      method: parsed.data.method,
      ...(parsed.data.method === "POST" ? { bodyType: parsed.data.bodyType as ScanBodyType } : {}),
      ...(parsed.data.method === "POST" && parsed.data.bodyType === "json" && parsed.data.bodyJson?.trim()
        ? { bodyJson: parsed.data.bodyJson.trim() }
        : {}),
      ...(parsed.data.method === "POST" && parsed.data.bodyType === "form" && parsed.data.bodyForm?.trim()
        ? { bodyForm: parsed.data.bodyForm.trim() }
        : {}),
      scenario: parsed.data.scenario,
      hints: normalizeExposureHints(parsed.data.hints),
    } satisfies SqlInjectionScanRequest);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : "SQL injection scan failed",
    });
  }
});

io.on("connection", (socket) => {
  socket.on("scan:join", (jobId: string) => {
    if (typeof jobId === "string" && jobId.length <= 128) {
      socket.join(scanRoom(jobId));
    }
  });
});

queueEvents.on("progress", ({ jobId, data }) => {
  io.to(scanRoom(jobId)).emit("scan:progress", {
    jobId,
    progress: data,
  });
});

queueEvents.on("completed", ({ jobId, returnvalue }) => {
  const result = parseScanResult(returnvalue);
  const progress: ScanProgress = {
    status: "completed",
    stage: "completed",
    percent: 100,
    message: "Scan hoan tat",
  };

  if (result) {
    progress.result = result;
  }

  io.to(scanRoom(jobId)).emit("scan:completed", {
    jobId,
    progress,
    ...(result ? { result } : {}),
  });
});

queueEvents.on("failed", ({ jobId, failedReason }) => {
  io.to(scanRoom(jobId)).emit("scan:failed", {
    jobId,
    progress: {
      status: "failed",
      stage: "failed",
      percent: 100,
      message: "Scan that bai",
      error: failedReason,
    } satisfies ScanProgress,
  });
});

await queueEvents.waitUntilReady();

httpServer.listen(env.port, () => {
  console.log(`API listening on http://localhost:${env.port}`);
});

function normalizeTargetUrl(input: string): string | null {
  try {
    const withProtocol = /^https?:\/\//i.test(input) ? input : `https://${input}`;
    const url = new URL(withProtocol);
    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

function scanRoom(jobId: string): string {
  return `scan:${jobId}`;
}

function normalizeExposureHints(hints: z.infer<typeof exposureScanSchema>["hints"]): ExposureScanHints {
  if (!hints) {
    return {};
  }

  return {
    ...(hints.backendLanguages ? { backendLanguages: hints.backendLanguages } : {}),
    ...(hints.frameworks ? { frameworks: hints.frameworks } : {}),
    ...(hints.databases ? { databases: hints.databases } : {}),
    ...(hints.webServer ? { webServer: hints.webServer } : {}),
    ...(hints.operatingSystem ? { operatingSystem: hints.operatingSystem } : {}),
  };
}

function parseScanResult(value: unknown): ScanResult | undefined {
  if (!value) {
    return undefined;
  }

  if (typeof value === "object") {
    return value as ScanResult;
  }

  if (typeof value !== "string") {
    return undefined;
  }

  try {
    return JSON.parse(value) as ScanResult;
  } catch {
    return undefined;
  }
}

async function shutdown(): Promise<void> {
  await Promise.allSettled([queueEvents.close(), scanQueue.close()]);
  httpServer.close();
}

process.on("SIGINT", () => {
  void shutdown().finally(() => process.exit(0));
});

process.on("SIGTERM", () => {
  void shutdown().finally(() => process.exit(0));
});
