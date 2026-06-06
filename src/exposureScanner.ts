import type {
  Evidence,
  ExposureCategory,
  ExposureFinding,
  ExposureScanHints,
  ExposureScanResult,
  FindingSeverity,
} from "./types.js";

interface ExposureCase {
  path: string;
  category: ExposureCategory;
  severity: FindingSeverity;
  description: string;
  signatures?: RegExp[];
  binarySignatures?: BinarySignature[];
  directoryListing?: boolean;
  requireSignature?: boolean;
}

type BinarySignature = "zip" | "gzip" | "7z" | "tar";

const MAX_CASES = 360;
const MAX_BYTES = 4096;
const REQUEST_TIMEOUT_MS = 2000;
const CONCURRENCY = 16;
const USER_AGENT = "ScanWEBCheckBug/1.2 exposure-check";

const ENV_SIGNATURES = [
  /(?:^|\n)[A-Z0-9_]{2,64}=.{1,}/,
  /(?:APP_KEY|APP_SECRET|DB_PASSWORD|DATABASE_URL|REDIS_URL|JWT_SECRET|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD)\s*=/i,
];

const SECRET_SIGNATURES = [
  /"?(?:secret|client_secret|access_token|refresh_token|private_key|password|api_key)"?\s*[:=]/i,
  /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/i,
];

const DOCKER_SIGNATURES = [
  /^(?:FROM|ARG|ENV|RUN|COPY|ADD|WORKDIR|CMD|ENTRYPOINT|EXPOSE)\b/im,
  /(?:^|\n)\s*(?:services|version|image|container_name|volumes|networks):/i,
];

const NODE_PACKAGE_SIGNATURES = [
  /"name"\s*:\s*"[^"]+"/i,
  /"(?:dependencies|devDependencies|scripts|engines|packageManager)"\s*:/i,
  /(?:package-lock|lockfileVersion|pnpm-lock|yarn lockfile|bun-lockfile)/i,
];

const NODE_CONFIG_SIGNATURES = [
  /\b(?:module\.exports|exports\.default|export default|require\(|import\s+.+\s+from)\b/i,
  /\b(?:process\.env|dotenv|express|koa|fastify|nestjs|next|nuxt|vite|webpack|pm2|nodemon)\b/i,
  /"(?:host|port|database|username|password|dialect|uri|url|secret|jwtSecret|mongo|redis)"\s*:/i,
];

const NODE_SOURCE_SIGNATURES = [
  /\b(?:require\(["']express["']\)|from ["']express["']|express\(\)|fastify\(|new Koa\(|NestFactory|createServer\(|app\.listen|server\.listen)\b/i,
  /\b(?:process\.env|module\.exports|exports\.|import\s+.+\s+from|require\()\b/i,
];

const NODE_ORM_SIGNATURES = [
  /\b(?:datasource|generator|provider\s*=|model\s+\w+|DATABASE_URL|PrismaClient)\b/i,
  /\b(?:sequelize|mongoose|typeorm|knex|mongodb|postgres|mysql|mariadb|sqlite|redis)\b/i,
  /"(?:type|dialect|database|username|password|host|port|url|uri)"\s*:/i,
  /^SQLite format 3/i,
];

const NODE_SOURCEMAP_SIGNATURES = [
  /"version"\s*:\s*3/i,
  /"sources"\s*:\s*\[/i,
  /"sourcesContent"\s*:\s*\[/i,
  /\/\/# sourceMappingURL=/i,
];

const PHP_SIGNATURES = [
  /<\?php/i,
  /\b(?:DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|ABSPATH|table_prefix)\b/i,
  /(?:mysqli_connect|new PDO|define\s*\()/i,
];

const WORDPRESS_SIGNATURES = [
  /\b(?:DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|NONCE_KEY|table_prefix|WP_DEBUG)\b/i,
  /wp-content|wp-includes|wordpress/i,
];

const VCS_SIGNATURES = [
  /\[core\]|repositoryformatversion|bare\s*=\s*false/i,
  /^ref:\s+refs\/heads\//im,
  /gitdir:/i,
];

const BACKUP_SIGNATURES = [
  /(?:-- MySQL dump|CREATE TABLE|INSERT INTO|PostgreSQL database dump|MariaDB dump)/i,
  /(?:<\?php|DB_PASSWORD|DATABASE_URL|wp-config|composer\.json|package\.json|node_modules)/i,
];

const SERVER_SIGNATURES = [
  /(?:server\s*\{|worker_processes|http\s*\{|location\s+\/|listen\s+\d+)/i,
  /(?:AuthUserFile|Require\s+valid-user|RewriteEngine|DirectoryIndex)/i,
];

const LOG_SIGNATURES = [
  /\[(?:error|warn|notice|debug)\]/i,
  /\b(?:PHP Fatal error|PHP Warning|Stack trace|GET|POST|nginx|apache)\b/i,
];

export async function runExposureScan(inputUrl: string, hints: ExposureScanHints): Promise<ExposureScanResult> {
  const startedAt = Date.now();
  const baseUrl = normalizeBaseUrl(inputUrl);
  const profile = normalizeHints(hints);
  const cases = buildExposureCases(profile, baseUrl).slice(0, MAX_CASES);
  const findings: ExposureFinding[] = [];
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < cases.length) {
      const index = cursor;
      cursor += 1;
      const item = cases[index];
      if (!item) {
        continue;
      }
      const finding = await checkExposureCase(baseUrl, item);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

  findings.sort((left, right) => {
    const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
    return (
      severityOrder[left.severity] - severityOrder[right.severity] ||
      right.confidence - left.confidence ||
      left.path.localeCompare(right.path)
    );
  });

  return {
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    baseUrl,
    checkedCount: cases.length,
    foundCount: findings.length,
    profile,
    findings,
    notes: [
      "Exposure scan checks a fixed list of common accidental public files on the same origin only.",
      "Evidence snippets are limited and redacted; this feature does not dump file contents.",
      "A clean result means no listed public file was confirmed, not that the site is fully secure.",
    ],
  };
}

function normalizeBaseUrl(inputUrl: string): string {
  const url = new URL(inputUrl);
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.toString();
}

function normalizeHints(hints: ExposureScanHints): ExposureScanHints {
  return {
    backendLanguages: uniqueStrings(hints.backendLanguages ?? []),
    frameworks: uniqueStrings(hints.frameworks ?? []),
    databases: uniqueStrings(hints.databases ?? []),
    ...(hints.webServer ? { webServer: hints.webServer } : {}),
    ...(hints.operatingSystem ? { operatingSystem: hints.operatingSystem } : {}),
  };
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean))).slice(0, 12);
}

function buildExposureCases(hints: ExposureScanHints, baseUrl: string): ExposureCase[] {
  const cases: ExposureCase[] = [
    ...environmentCases(),
    ...secretCases(),
    ...dockerCases(),
    ...vcsCases(),
  ];

  if (hasHint(hints, "php")) {
    cases.push(...phpCases());
  }

  if (hasNodeHint(hints)) {
    cases.push(...nodeCases());
  }

  if (hasHint(hints, "wordpress")) {
    cases.push(...wordpressCases());
  }

  cases.push(...backupCases(baseUrl), ...serverCases());

  if (hasHint(hints, "nginx") || hasHint(hints, "linux") || hasHint(hints, "unix")) {
    cases.push(...nginxLinuxCases());
  }

  cases.push(...logCases(), ...directoryCases());

  return dedupeCases(cases);
}

function hasNodeHint(hints: ExposureScanHints): boolean {
  return [
    "node",
    "node.js",
    "nodejs",
    "express",
    "fastify",
    "koa",
    "nestjs",
    "nest.js",
    "next.js",
    "nextjs",
    "nuxt",
    "javascript",
    "typescript",
  ].some((needle) => hasHint(hints, needle));
}

function hasHint(hints: ExposureScanHints, needle: string): boolean {
  const haystack = [
    ...(hints.backendLanguages ?? []),
    ...(hints.frameworks ?? []),
    ...(hints.databases ?? []),
    hints.webServer ?? "",
    hints.operatingSystem ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function environmentCases(): ExposureCase[] {
  return [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.prod",
    "/.env.development",
    "/.env.dev",
    "/.env.staging",
    "/.env.stage",
    "/.env.test",
    "/.env.testing",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.save",
    "/.env.example",
    "/.env.sample",
    "/.env.dist",
    "/.env.php",
    "/.env~",
    "/env",
    "/env.local",
    "/config/.env",
    "/app/.env",
    "/api/.env",
    "/backend/.env",
    "/public/.env",
    "/html/.env",
    "/www/.env",
  ].map((path) => ({
    path,
    category: "environment",
    severity: "high",
    description: "Environment file may expose credentials or runtime configuration",
    signatures: ENV_SIGNATURES,
    requireSignature: true,
  }));
}

function secretCases(): ExposureCase[] {
  return [
    "/secrets.json",
    "/secret.json",
    "/config/secrets.json",
    "/config/secret.json",
    "/credentials.json",
    "/credential.json",
    "/service-account.json",
    "/serviceAccount.json",
    "/google-services.json",
    "/firebase.json",
    "/.npmrc",
    "/.dockercfg",
    "/.docker/config.json",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/.aws/credentials",
    "/.aws/config",
  ].map((path) => ({
    path,
    category: "secret",
    severity: "high",
    description: "Secret or credential file appears publicly readable",
    signatures: SECRET_SIGNATURES,
    requireSignature: true,
  }));
}

function dockerCases(): ExposureCase[] {
  return [
    "/Dockerfile",
    "/Dockerfile.dev",
    "/Dockerfile.prod",
    "/Dockerfile.production",
    "/dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.override.yml",
    "/docker-compose.prod.yml",
    "/docker-compose.production.yml",
    "/compose.yml",
    "/compose.yaml",
    "/.dockerignore",
    "/docker/.env",
    "/docker-compose.env",
  ].map((path) => ({
    path,
    category: "docker",
    severity: path.includes(".env") ? "high" : "medium",
    description: "Docker configuration may reveal internal services, image names, or credentials",
    signatures: [...DOCKER_SIGNATURES, ...ENV_SIGNATURES],
    requireSignature: true,
  }));
}

function vcsCases(): ExposureCase[] {
  return [
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.svn/entries",
    "/.hg/hgrc",
    "/.bzr/branch/branch.conf",
    "/.gitignore",
  ].map((path) => ({
    path,
    category: "vcs",
    severity: path === "/.gitignore" ? "low" : "high",
    description: "Version-control metadata appears publicly readable",
    signatures: VCS_SIGNATURES,
    requireSignature: path !== "/.gitignore",
  }));
}

function nodeCases(): ExposureCase[] {
  const packageRoots = ["", "/app", "/api", "/backend", "/server", "/service", "/node", "/client", "/web"];
  const packageFiles = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "rush.json",
    "lerna.json",
    "nx.json",
    "turbo.json",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".nvmrc",
    ".node-version",
  ];

  const configRoots = ["", "/config", "/configs", "/src/config", "/app/config", "/server/config", "/api/config", "/backend/config"];
  const configFiles = [
    "default.json",
    "production.json",
    "prod.json",
    "development.json",
    "dev.json",
    "staging.json",
    "stage.json",
    "test.json",
    "local.json",
    "database.json",
    "db.json",
    "mongo.json",
    "mongodb.json",
    "redis.json",
    "mail.json",
    "auth.json",
    "jwt.json",
    "secrets.json",
    "secret.json",
    "config.json",
    "config.js",
    "config.cjs",
    "config.mjs",
    "database.js",
    "db.js",
    "redis.js",
    "mongo.js",
    "mongodb.js",
    "secrets.js",
    "secret.js",
  ];

  const sourcePaths = [
    "/server.js",
    "/server.cjs",
    "/server.mjs",
    "/server.ts",
    "/app.js",
    "/app.cjs",
    "/app.mjs",
    "/app.ts",
    "/index.js",
    "/index.cjs",
    "/index.mjs",
    "/index.ts",
    "/main.js",
    "/main.ts",
    "/src/server.js",
    "/src/server.ts",
    "/src/app.js",
    "/src/app.ts",
    "/src/index.js",
    "/src/index.ts",
    "/src/main.js",
    "/src/main.ts",
    "/dist/server.js",
    "/dist/app.js",
    "/dist/index.js",
    "/dist/main.js",
    "/build/server.js",
    "/build/app.js",
    "/build/index.js",
    "/build/main.js",
    "/server/index.js",
    "/server/app.js",
    "/server/main.js",
    "/api/server.js",
    "/api/app.js",
    "/backend/server.js",
    "/backend/app.js",
  ];

  const frameworkPaths = [
    "/next.config.js",
    "/next.config.mjs",
    "/next.config.ts",
    "/nuxt.config.js",
    "/nuxt.config.ts",
    "/nest-cli.json",
    "/nestconfig.json",
    "/vite.config.js",
    "/vite.config.ts",
    "/webpack.config.js",
    "/webpack.prod.js",
    "/webpack.dev.js",
    "/rollup.config.js",
    "/babel.config.js",
    "/tsconfig.json",
    "/tsconfig.build.json",
    "/jsconfig.json",
    "/nodemon.json",
    "/ecosystem.config.js",
    "/ecosystem.config.cjs",
    "/pm2.config.js",
    "/process.json",
    "/forever.json",
    "/.pm2/dump.pm2",
    "/.pm2/module_conf.json",
  ];

  const ormPaths = [
    "/prisma/schema.prisma",
    "/prisma/dev.db",
    "/prisma/prod.db",
    "/prisma/database.db",
    "/prisma/migrations/migration_lock.toml",
    "/schema.prisma",
    "/ormconfig.json",
    "/ormconfig.js",
    "/ormconfig.ts",
    "/typeorm.config.js",
    "/typeorm.config.ts",
    "/sequelize.config.js",
    "/sequelize.config.json",
    "/knexfile.js",
    "/knexfile.ts",
    "/database.sqlite",
    "/database.sqlite3",
    "/db.sqlite",
    "/db.sqlite3",
    "/dev.db",
    "/data.db",
    "/data/database.sqlite",
    "/storage/database.sqlite",
  ];

  const nextNuxtPaths = [
    "/.next/BUILD_ID",
    "/.next/routes-manifest.json",
    "/.next/build-manifest.json",
    "/.next/prerender-manifest.json",
    "/.next/react-loadable-manifest.json",
    "/.next/server/pages-manifest.json",
    "/.next/server/app-paths-manifest.json",
    "/.next/server/middleware-manifest.json",
    "/.next/server/required-server-files.json",
    "/.next/server/next-font-manifest.json",
    "/.next/server/server-reference-manifest.json",
    "/.nuxt/nitro.json",
    "/.nuxt/dist/server/server.mjs",
    "/.nuxt/dist/server/client.manifest.mjs",
    "/.output/nitro.json",
    "/.output/server/index.mjs",
    "/.output/server/chunks/app/server.mjs",
    "/.output/public/_nuxt/builds/meta.json",
  ];

  const sourceMapPaths = [
    "/server.js.map",
    "/app.js.map",
    "/index.js.map",
    "/main.js.map",
    "/bundle.js.map",
    "/vendor.js.map",
    "/runtime.js.map",
    "/dist/server.js.map",
    "/dist/app.js.map",
    "/dist/index.js.map",
    "/dist/main.js.map",
    "/build/server.js.map",
    "/build/app.js.map",
    "/build/index.js.map",
    "/build/main.js.map",
    "/public/js/app.js.map",
    "/public/js/main.js.map",
    "/static/js/main.js.map",
    "/static/js/bundle.js.map",
    "/assets/main.js.map",
    "/assets/index.js.map",
    "/_next/static/chunks/main.js.map",
    "/_next/static/chunks/webpack.js.map",
    "/_next/static/chunks/framework.js.map",
    "/_nuxt/app.js.map",
    "/_nuxt/entry.js.map",
  ];

  const nodeModulesPaths = [
    "/node_modules/.package-lock.json",
    "/node_modules/express/package.json",
    "/node_modules/fastify/package.json",
    "/node_modules/koa/package.json",
    "/node_modules/@nestjs/core/package.json",
    "/node_modules/next/package.json",
    "/node_modules/nuxt/package.json",
    "/node_modules/@prisma/client/package.json",
    "/node_modules/prisma/package.json",
    "/node_modules/mongoose/package.json",
    "/node_modules/sequelize/package.json",
    "/node_modules/typeorm/package.json",
    "/node_modules/pg/package.json",
    "/node_modules/mysql2/package.json",
    "/node_modules/redis/package.json",
    "/node_modules/ioredis/package.json",
    "/node_modules/jsonwebtoken/package.json",
    "/node_modules/bcrypt/package.json",
    "/node_modules/dotenv/package.json",
  ];

  const logPaths = [
    "/npm-debug.log",
    "/yarn-error.log",
    "/pnpm-debug.log",
    "/node.log",
    "/server.log",
    "/pm2.log",
    "/logs/node.log",
    "/logs/server.log",
    "/logs/app.log",
    "/logs/api.log",
    "/logs/worker.log",
    "/logs/pm2.log",
    "/.pm2/logs/app-error.log",
    "/.pm2/logs/app-out.log",
    "/.pm2/logs/server-error.log",
    "/.pm2/logs/server-out.log",
  ];

  return [
    ...pathsInDirs(packageRoots, packageFiles).map((path) =>
      nodeCase(path, "low", "Node package or lock file may reveal dependencies and runtime scripts", NODE_PACKAGE_SIGNATURES),
    ),
    ...pathsInDirs(configRoots, configFiles).map((path) =>
      nodeCase(path, nodeConfigSeverity(path), "Node configuration file may expose runtime settings or secrets", [
        ...NODE_CONFIG_SIGNATURES,
        ...SECRET_SIGNATURES,
        ...ENV_SIGNATURES,
      ]),
    ),
    ...sourcePaths.map((path) =>
      nodeCase(path, "medium", "Node server source file appears publicly readable", [
        ...NODE_SOURCE_SIGNATURES,
        ...NODE_CONFIG_SIGNATURES,
      ]),
    ),
    ...frameworkPaths.map((path) =>
      nodeCase(path, "low", "Node build or process configuration appears publicly readable", NODE_CONFIG_SIGNATURES),
    ),
    ...ormPaths.map((path) =>
      nodeCase(path, nodeDataSeverity(path), "Node ORM or local database file appears publicly readable", [
        ...NODE_ORM_SIGNATURES,
        ...SECRET_SIGNATURES,
        ...ENV_SIGNATURES,
      ], nodeBinarySignatures(path)),
    ),
    ...nextNuxtPaths.map((path) =>
      nodeCase(path, "medium", "Next.js or Nuxt server build artifact appears publicly readable", [
        ...NODE_CONFIG_SIGNATURES,
        ...NODE_PACKAGE_SIGNATURES,
      ]),
    ),
    ...sourceMapPaths.map((path) =>
      nodeCase(path, "medium", "JavaScript source map may expose original source code", NODE_SOURCEMAP_SIGNATURES),
    ),
    ...nodeModulesPaths.map((path) =>
      nodeCase(path, "medium", "Public node_modules dependency metadata suggests server files may be exposed", [
        ...NODE_PACKAGE_SIGNATURES,
        /node_modules/i,
      ]),
    ),
    ...logPaths.map((path) =>
      nodeCase(path, "medium", "Node application log appears publicly readable", [
        ...LOG_SIGNATURES,
        /\b(?:node|npm|yarn|pm2|express|fastify|nestjs|UnhandledPromiseRejection|Error:|TypeError:)\b/i,
      ]),
    ),
  ];
}

function phpCases(): ExposureCase[] {
  return [
    "/composer.json",
    "/composer.lock",
    "/auth.json",
    "/config.php",
    "/config/config.php",
    "/app/config.php",
    "/includes/config.php",
    "/database.php",
    "/db.php",
    "/db_config.php",
    "/connection.php",
    "/settings.php",
    "/local.php",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug.php",
    "/install.php",
    "/setup.php",
  ].map((path) => ({
    path,
    category: "php",
    severity: phpSeverity(path),
    description: "PHP application file may expose source, dependencies, or debug information",
    signatures: [...PHP_SIGNATURES, ...SECRET_SIGNATURES],
    requireSignature: !["/composer.json", "/composer.lock"].includes(path),
  }));
}

function wordpressCases(): ExposureCase[] {
  return [
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/wp-config.bak",
    "/wp-config.old",
    "/wp-config.txt",
    "/wp-config.php.txt",
    "/wp-config.php.backup",
    "/wp-config.php.orig",
    "/wp-config.php.swp",
    "/wp-config.local.php",
    "/wp-config-dev.php",
    "/wp-config-prod.php",
    "/wordpress/wp-config.php",
    "/blog/wp-config.php",
    "/wp/wp-config.php",
    "/old/wp-config.php",
    "/backup/wp-config.php",
    "/site/wp-config.php",
    "/wp-content/debug.log",
    "/wp-content/uploads/debug.log",
    "/wp-content/uploads/.env",
    "/wp-content/uploads/wp-config.php",
    "/wp-admin/error_log",
    "/wp-content/error_log",
  ].map((path) => ({
    path,
    category: "wordpress",
    severity: wordpressSeverity(path),
    description: "WordPress-sensitive file or debug endpoint appears publicly readable",
    signatures: [...WORDPRESS_SIGNATURES, ...PHP_SIGNATURES, ...LOG_SIGNATURES],
    requireSignature: true,
  }));
}

function backupCases(baseUrl: string): ExposureCase[] {
  const host = new URL(baseUrl).hostname;
  const hostParts = host.split(".").filter(Boolean);
  const shortHost = hostParts.length > 2 ? hostParts.slice(-3, -2)[0] : hostParts[0];
  const dynamicNames = uniqueStrings([host, host.replace(/^www\./, ""), shortHost ?? ""]);
  const dynamicPaths = dynamicNames.flatMap((name) => [
    `/${name}.zip`,
    `/${name}.tar.gz`,
    `/${name}.sql`,
    `/${name}.bak`,
  ]);

  return [
    "/backup.zip",
    "/backup.tar",
    "/backup.tar.gz",
    "/backup.tgz",
    "/backup.sql",
    "/backup.sql.gz",
    "/backup.7z",
    "/backup.rar",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/mysql.sql",
    "/site.zip",
    "/website.zip",
    "/www.zip",
    "/www.tar.gz",
    "/public_html.zip",
    "/public_html.tar.gz",
    "/htdocs.zip",
    "/html.zip",
    "/source.zip",
    "/src.zip",
    "/old.zip",
    "/bak.zip",
    "/backup.bak",
    "/database.bak",
    ...dynamicPaths,
  ].map((path) => ({
    path,
    category: "backup",
    severity: "high",
    description: "Backup or dump file appears publicly readable",
    signatures: BACKUP_SIGNATURES,
    binarySignatures: ["zip", "gzip", "7z", "tar"],
    requireSignature: true,
  }));
}

function serverCases(): ExposureCase[] {
  return [
    "/nginx.conf",
    "/conf/nginx.conf",
    "/etc/nginx/nginx.conf",
    "/default.conf",
    "/vhost.conf",
    "/server.conf",
    "/sites-enabled/default",
    "/sites-available/default",
    "/.htpasswd",
    "/.htaccess",
    "/web.config",
  ].map((path) => ({
    path,
    category: "server",
    severity: path.includes("passwd") ? "high" : "medium",
    description: "Server configuration file appears publicly readable",
    signatures: SERVER_SIGNATURES,
    requireSignature: true,
  }));
}

function nginxLinuxCases(): ExposureCase[] {
  return [
    "/etc/passwd",
    "/proc/self/environ",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/nginx_status",
  ].map((path) => ({
    path,
    category: path.includes("log") ? "log" : "server",
    severity: path.includes("passwd") || path.includes("environ") ? "high" : "medium",
    description: "Linux/nginx file path appears publicly readable",
    signatures: path.includes("passwd")
      ? [/root:x:|www-data:x:|daemon:x:/i]
      : path.includes("environ")
        ? ENV_SIGNATURES
        : [...LOG_SIGNATURES, ...SERVER_SIGNATURES],
    requireSignature: true,
  }));
}

function logCases(): ExposureCase[] {
  return [
    "/error.log",
    "/access.log",
    "/debug.log",
    "/php_errors.log",
    "/php-error.log",
    "/logs/error.log",
    "/logs/access.log",
    "/logs/debug.log",
    "/storage/logs/laravel.log",
    "/application.log",
    "/app.log",
  ].map((path) => ({
    path,
    category: "log",
    severity: "medium",
    description: "Application or server log appears publicly readable",
    signatures: LOG_SIGNATURES,
    requireSignature: true,
  }));
}

function directoryCases(): ExposureCase[] {
  return [
    "/backup/",
    "/backups/",
    "/bak/",
    "/old/",
    "/tmp/",
    "/temp/",
    "/logs/",
    "/private/",
    "/config/",
    "/db/",
    "/database/",
    "/uploads/",
    "/files/",
    "/wp-content/uploads/",
    "/wp-content/backups/",
  ].map((path) => ({
    path,
    category: "directory",
    severity: "medium",
    description: "Directory listing appears enabled",
    directoryListing: true,
    requireSignature: true,
  }));
}

function dedupeCases(cases: ExposureCase[]): ExposureCase[] {
  const seen = new Set<string>();
  const deduped: ExposureCase[] = [];
  for (const item of cases) {
    const normalizedPath = normalizeCasePath(item.path);
    if (seen.has(normalizedPath)) {
      continue;
    }
    seen.add(normalizedPath);
    deduped.push({ ...item, path: normalizedPath });
  }
  return deduped;
}

function normalizeCasePath(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
}

function pathsInDirs(dirs: string[], files: string[]): string[] {
  const paths: string[] = [];
  for (const dir of dirs) {
    const prefix = dir ? normalizeCasePath(dir).replace(/\/$/, "") : "";
    for (const file of files) {
      paths.push(`${prefix}/${file}`.replace(/\/{2,}/g, "/"));
    }
  }
  return paths;
}

function nodeCase(
  path: string,
  severity: FindingSeverity,
  description: string,
  signatures: RegExp[],
  binarySignatures?: BinarySignature[],
): ExposureCase {
  return {
    path,
    category: "node",
    severity,
    description,
    signatures,
    ...(binarySignatures ? { binarySignatures } : {}),
    requireSignature: true,
  };
}

function nodeConfigSeverity(path: string): FindingSeverity {
  if (/(secret|secrets|auth|jwt|database|db|mongo|redis|local|production|prod)/i.test(path)) {
    return "high";
  }
  return "medium";
}

function nodeDataSeverity(path: string): FindingSeverity {
  if (/\.(?:db|sqlite|sqlite3)$/i.test(path)) {
    return "high";
  }
  if (/schema\.prisma|ormconfig|sequelize|knex|typeorm/i.test(path)) {
    return "medium";
  }
  return "low";
}

function nodeBinarySignatures(path: string): BinarySignature[] | undefined {
  if (/\.(?:zip|gz|tgz|7z|tar)$/i.test(path)) {
    return ["zip", "gzip", "7z", "tar"];
  }
  return undefined;
}

function phpSeverity(path: string): FindingSeverity {
  if (path.includes("config") || path.includes("db") || path.includes("connection") || path.includes("auth")) {
    return "high";
  }
  if (path.includes("phpinfo") || path.includes("debug") || path.includes("info")) {
    return "medium";
  }
  return "low";
}

function wordpressSeverity(path: string): FindingSeverity {
  if (path.includes("wp-config") || path.includes(".env")) {
    return "high";
  }
  if (path.includes("debug") || path.includes("error_log")) {
    return "medium";
  }
  return "low";
}

async function checkExposureCase(baseUrl: string, item: ExposureCase): Promise<ExposureFinding | null> {
  const targetUrl = new URL(item.path, baseUrl).toString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: "text/plain,application/json,application/octet-stream,*/*;q=0.2",
        Range: `bytes=0-${MAX_BYTES - 1}`,
        "User-Agent": USER_AGENT,
      },
    });

    if (!isReadableStatus(response.status)) {
      return null;
    }

    const body = await readLimitedBody(response, MAX_BYTES);
    const text = body.toString("utf8");
    const contentType = response.headers.get("content-type") ?? undefined;
    const match = matchExposure(item, body, text, contentType);

    if (!match) {
      return null;
    }

    return {
      path: item.path,
      url: targetUrl,
      category: item.category,
      severity: item.severity,
      statusCode: response.status,
      ...(contentType ? { contentType } : {}),
      bytesRead: body.length,
      confidence: match.confidence,
      description: item.description,
      evidence: buildEvidence(item, match, text, contentType),
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function isReadableStatus(statusCode: number): boolean {
  return statusCode >= 200 && statusCode < 300;
}

async function readLimitedBody(response: Response, maxBytes: number): Promise<Buffer> {
  const reader = response.body?.getReader();
  if (!reader) {
    return Buffer.alloc(0);
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

  return Buffer.concat(chunks, total);
}

function matchExposure(
  item: ExposureCase,
  body: Buffer,
  text: string,
  contentType: string | undefined,
): { confidence: number; matchedBy: string } | null {
  if (!body.length) {
    return null;
  }

  if (item.directoryListing && looksLikeDirectoryListing(text)) {
    return { confidence: 0.86, matchedBy: "directory listing marker" };
  }

  const binaryMatch = item.binarySignatures?.find((signature) => matchesBinarySignature(body, signature));
  if (binaryMatch) {
    return { confidence: 0.86, matchedBy: `${binaryMatch} file signature` };
  }

  const signature = item.signatures?.find((pattern) => pattern.test(text));
  if (signature) {
    return { confidence: 0.88, matchedBy: signature.source };
  }

  if (looksLikeHtmlFallback(text, contentType)) {
    return null;
  }

  if (item.requireSignature) {
    return null;
  }

  return { confidence: 0.48, matchedBy: "HTTP 2xx response with non-HTML body" };
}

function matchesBinarySignature(body: Buffer, signature: BinarySignature): boolean {
  if (signature === "zip") {
    return body.length >= 4 && body[0] === 0x50 && body[1] === 0x4b && body[2] === 0x03 && body[3] === 0x04;
  }
  if (signature === "gzip") {
    return body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b;
  }
  if (signature === "7z") {
    return body.length >= 6 && body.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]));
  }
  return body.length > 265 && body.subarray(257, 262).toString("ascii") === "ustar";
}

function looksLikeHtmlFallback(text: string, contentType: string | undefined): boolean {
  const lower = text.slice(0, 1200).toLowerCase();
  const htmlContent = contentType?.toLowerCase().includes("text/html") || /<html[\s>]|<!doctype html/i.test(lower);
  if (!htmlContent) {
    return false;
  }

  return !/(DB_PASSWORD|DATABASE_URL|-----BEGIN|CREATE TABLE|wp-config|Index of \/|Parent Directory)/i.test(text);
}

function looksLikeDirectoryListing(text: string): boolean {
  return /<title>Index of\s+\/|Index of\s+\/|Parent Directory/i.test(text);
}

function buildEvidence(
  item: ExposureCase,
  match: { confidence: number; matchedBy: string },
  text: string,
  contentType: string | undefined,
): Evidence[] {
  const evidence: Evidence[] = [
    {
      source: "http:get",
      detail: `Matched ${match.matchedBy}`,
      value: item.path,
    },
  ];

  if (contentType) {
    evidence.push({
      source: "header:content-type",
      detail: "Response content type",
      value: contentType,
    });
  }

  const snippet = redactSnippet(text);
  if (snippet) {
    evidence.push({
      source: "body:snippet",
      detail: "Redacted first bytes only",
      value: snippet,
    });
  }

  return evidence.slice(0, 4);
}

function redactSnippet(text: string): string {
  return text
    .replace(/\0/g, "")
    .split(/\r?\n/)
    .slice(0, 8)
    .join("\n")
    .replace(
      /((?:SECRET|TOKEN|PASSWORD|PASS|PWD|KEY|DATABASE_URL|DB_PASSWORD|PRIVATE_KEY|ACCESS_KEY|MONGODB_URI|MONGO_URI|REDIS_URL|JWT_SECRET|SESSION_SECRET|COOKIE_SECRET)[A-Z0-9_ -]*\s*[:=]\s*)(["']?)[^\r\n"']+/gi,
      "$1$2[redacted]",
    )
    .replace(
      /("(?:secret|token|password|private_key|client_secret|access_token|api_key)"\s*:\s*")([^"]+)(")/gi,
      "$1[redacted]$3",
    )
    .slice(0, 500);
}
