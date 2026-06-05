import { Queue, QueueEvents, type ConnectionOptions, type JobsOptions } from "bullmq";

import { env } from "./config.js";
import type { ScanJobData, ScanResult } from "./types.js";

export const SCAN_QUEUE_NAME = "scan-jobs";

const defaultJobOptions: JobsOptions = {
  attempts: 1,
  removeOnComplete: {
    age: 3600,
    count: 200,
  },
  removeOnFail: {
    age: 24 * 3600,
    count: 500,
  },
};

export function createRedisConnection(): ConnectionOptions {
  const url = new URL(env.redisUrl);
  const connection: Record<string, unknown> = {
    host: url.hostname,
    port: Number(url.port || 6379),
    maxRetriesPerRequest: null,
  };

  const db = url.pathname ? Number(url.pathname.slice(1)) : NaN;
  if (url.username) {
    connection.username = decodeURIComponent(url.username);
  }
  if (url.password) {
    connection.password = decodeURIComponent(url.password);
  }
  if (Number.isInteger(db)) {
    connection.db = db;
  }
  if (url.protocol === "rediss:") {
    connection.tls = {};
  }

  return connection as ConnectionOptions;
}

export function createScanQueue() {
  return new Queue<ScanJobData, ScanResult>(SCAN_QUEUE_NAME, {
    connection: createRedisConnection(),
    defaultJobOptions,
  });
}

export function createScanQueueEvents(): QueueEvents {
  return new QueueEvents(SCAN_QUEUE_NAME, {
    connection: createRedisConnection(),
  });
}
