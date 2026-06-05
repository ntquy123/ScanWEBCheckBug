import { Worker, type Job } from "bullmq";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { env } from "./config.js";
import { createRedisConnection, SCAN_QUEUE_NAME } from "./queue.js";
import type { ScanJobData, ScanProgress, ScanResult } from "./types.js";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scannerPath = path.join(rootDir, "worker", "scanner.py");

const worker = new Worker<ScanJobData, ScanResult>(
  SCAN_QUEUE_NAME,
  async (job) => runPythonScanner(job),
  {
    connection: createRedisConnection(),
    concurrency: env.workerConcurrency,
  },
);

worker.on("completed", (job) => {
  console.log(`Scan job ${job.id} completed`);
});

worker.on("failed", (job, error) => {
  console.error(`Scan job ${job?.id ?? "unknown"} failed: ${error.message}`);
});

console.log(`Scanner worker ready. Python binary: ${env.pythonBin}`);

async function runPythonScanner(job: Job<ScanJobData, ScanResult>): Promise<ScanResult> {
  await job.updateProgress({
    status: "running",
    stage: "starting",
    percent: 5,
    message: "Dang khoi dong scanner Python",
  } satisfies ScanProgress);

  return new Promise<ScanResult>((resolve, reject) => {
    let stderr = "";
    let stdoutBuffer = "";
    let result: ScanResult | undefined;

    const child = spawn(env.pythonBin, [scannerPath, job.data.url], {
      env: {
        ...process.env,
        ALLOW_PRIVATE_TARGETS: env.allowPrivateTargets ? "1" : "0",
        SCAN_TIMEOUT_SECONDS: String(Math.ceil(env.scanTimeoutMs / 1000)),
      },
      windowsHide: true,
    });

    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Scanner qua thoi gian ${env.scanTimeoutMs}ms`));
    }, env.scanTimeoutMs + 5000);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuffer += chunk.toString("utf8");
      const lines = stdoutBuffer.split(/\r?\n/);
      stdoutBuffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.trim()) {
          continue;
        }

        handleScannerLine(line, job, (nextResult) => {
          result = nextResult;
        });
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);

      if (stdoutBuffer.trim()) {
        handleScannerLine(stdoutBuffer, job, (nextResult) => {
          result = nextResult;
        });
      }

      if (code !== 0) {
        reject(new Error(stderr.trim() || `Scanner exited with code ${code}`));
        return;
      }

      if (!result) {
        reject(new Error("Scanner khong tra ve ket qua hop le"));
        return;
      }

      resolve(result);
    });
  });
}

function handleScannerLine(
  line: string,
  job: Job<ScanJobData, ScanResult>,
  setResult: (result: ScanResult) => void,
): void {
  try {
    const event = JSON.parse(line) as
      | { type: "progress"; progress: ScanProgress }
      | { type: "result"; result: ScanResult };

    if (event.type === "progress") {
      void job.updateProgress(event.progress);
      return;
    }

    setResult(event.result);
  } catch (error) {
    console.error(`Cannot parse scanner output: ${(error as Error).message}`);
  }
}

async function shutdown(): Promise<void> {
  await worker.close();
}

process.on("SIGINT", () => {
  void shutdown().finally(() => process.exit(0));
});

process.on("SIGTERM", () => {
  void shutdown().finally(() => process.exit(0));
});
