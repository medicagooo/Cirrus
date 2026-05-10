import { Hono } from "hono";
import { jsxRenderer } from "hono/jsx-renderer";
import { createObjectStorage, storageBackend, storageLabel, type ObjectStorage, type StorageEnv } from "./object-storage";
import {
  addFriend,
  AppError,
  copyFiles,
  createFileFromCompletedUpload,
  createFileFromUpload,
  createRegisteredUser,
  createShare,
  deleteDriveFile,
  getActiveFileMeta,
  getShare,
  getDirectMessages,
  getUserPasswordCredentials,
  getUserProfiles,
  getUserTagGrants,
  hashUserPassword,
  incrementDownload,
  listFiles,
  markUserNotificationsRead,
  objectKey,
  cleanDescription,
  cleanTags,
  parseOptionalDate,
  renameFile,
  removeFriend,
  resolveShareFiles,
  resolveShareFilesByIds,
  sendDirectMessage,
  setUserVisibleTags,
  updateOwnUserProfile,
  updateUserPassword,
  updateUserTagGrants,
  updateUserProfiles,
  updateFileDescription,
  updateFileTags,
  verifySharePassword,
  verifyUserPasswordHash,
  userAccountsFromCredentials,
  type CreateShareInput,
  type DirectMessage,
  type DriveFileMeta,
  type MergeMode,
  type ShareRecord,
  type StoredUserAccount,
  type UserPasswordCredentials,
  type UserTagGrants,
  type UserProfiles,
} from "./storage";
import { createStoredZipStream } from "./zip";

type UserRole = "admin" | "user";

interface AuthEnv {
  AUTH_USERS?: string;
  ALLOW_UNCONFIGURED_AUTH?: string;
  CSRF_SECRET?: string;
  API_RATE_LIMIT_PER_MINUTE?: string;
  AUTH_RATE_LIMIT_PER_MINUTE?: string;
  AUTH_IDENTITY_RATE_LIMIT_PER_MINUTE?: string;
  SHARE_VERIFY_RATE_LIMIT_PER_MINUTE?: string;
  MAX_FILE_BYTES?: string;
  UPLOAD_CHUNK_BYTES?: string;
  MAX_JSON_BYTES?: string;
  MAX_SELECTED_FILES?: string;
  MAX_SHARE_FILES?: string;
}

interface AuthUser {
  name: string;
  password: string;
  role: UserRole;
  source: "env" | "registered";
}

interface AuthSession {
  name: string;
  role: UserRole;
  baseRole: UserRole;
  configured: boolean;
  csrfSeed: string;
}

type Bindings = StorageEnv & AuthEnv;

interface AppVariables {
  session: AuthSession;
  nonce: string;
  csrfToken: string;
}

const app = new Hono<{ Bindings: Bindings; Variables: AppVariables }>();

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024;
const DEFAULT_MAX_JSON_BYTES = 64 * 1024;
const DEFAULT_MAX_SELECTED_FILES = 500;
const DEFAULT_MAX_SHARE_FILES = 100;
const DEFAULT_API_RATE_LIMIT_PER_MINUTE = 300;
const DEFAULT_AUTH_RATE_LIMIT_PER_MINUTE = 60;
const DEFAULT_AUTH_IDENTITY_RATE_LIMIT_PER_MINUTE = 20;
const DEFAULT_SHARE_VERIFY_RATE_LIMIT_PER_MINUTE = 30;
const SESSION_COOKIE = "cirrus_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 14;
const SHARE_DOWNLOAD_TICKET_SECONDS = 120;

interface RateBucket {
  count: number;
  resetAt: number;
}

interface ShareDownloadTicketPayload {
  code: string;
  allowedIds: string[];
  expiresAt: number;
  nonce: string;
}

const rateBuckets =
  ((globalThis as typeof globalThis & { __cirrusRateBuckets?: Map<string, RateBucket> }).__cirrusRateBuckets ??=
    new Map<string, RateBucket>());

function jsonError(error: unknown) {
  if (error instanceof AppError) {
    return {
      message: error.message,
      status: error.status,
    };
  }

  if (error instanceof Error) {
    return {
      message: "服务暂时不可用",
      status: 500,
    };
  }

  return {
    message: "服务暂时不可用",
    status: 500,
  };
}

function errorResponse(message: string, status: number) {
  return Response.json(
    { error: message },
    {
      status,
      headers: {
        "Cache-Control": "no-store",
      },
    },
  );
}

function isUploadedFile(value: unknown): value is File {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<File>;
  const fileConstructor = (globalThis as typeof globalThis & { File?: typeof File }).File;
  const isFile =
    typeof fileConstructor === "function"
      ? value instanceof fileConstructor
      : value instanceof Blob && typeof candidate.name === "string";
  return isFile && typeof candidate.size === "number" && candidate.size > 0;
}

function attachmentName(name: string) {
  const fallback = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_") || "download";
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function jsonBody<T>(request: Request, maxBytes = DEFAULT_MAX_JSON_BYTES) {
  const contentLength = parseContentLength(request.headers.get("Content-Length"));
  if (contentLength !== null && contentLength > maxBytes) {
    throw new AppError("请求体过大", 413);
  }

  let text = "";
  try {
    text = await request.text();
  } catch {
    throw new AppError("请求体读取失败");
  }

  if (new TextEncoder().encode(text).byteLength > maxBytes) {
    throw new AppError("请求体过大", 413);
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new AppError("请求体不是有效 JSON");
  }
}

function idsFromValue(value: unknown, maxIds = DEFAULT_MAX_SELECTED_FILES) {
  if (!Array.isArray(value)) throw new AppError("请选择文件");
  const ids = value
    .filter((id): id is string => typeof id === "string" && isUuid(id))
    .slice(0, maxIds + 1);
  if (!ids.length) throw new AppError("请选择文件");
  if (ids.length > maxIds) throw new AppError("选择的文件过多", 413);
  return Array.from(new Set(ids));
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function randomToken(bytes = 18) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return base64Url(values);
}

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function runtimeSessionSecret() {
  const globalScope = globalThis as typeof globalThis & { __cirrusRuntimeSessionSecret?: string };
  globalScope.__cirrusRuntimeSessionSecret ??= randomToken(32);
  return globalScope.__cirrusRuntimeSessionSecret;
}

function parseContentLength(value: string | null) {
  if (!value) return null;
  const length = Number(value);
  return Number.isSafeInteger(length) && length >= 0 ? length : null;
}

function parsePositiveInt(value: string | undefined, fallback: number, max = Number.MAX_SAFE_INTEGER) {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

function maxFileBytes(env: Bindings) {
  return parsePositiveInt(env.MAX_FILE_BYTES, DEFAULT_MAX_FILE_BYTES);
}

function maxJsonBytes(env: Bindings) {
  return parsePositiveInt(env.MAX_JSON_BYTES, DEFAULT_MAX_JSON_BYTES, 1024 * 1024);
}

function maxSelectedFiles(env: Bindings) {
  return parsePositiveInt(env.MAX_SELECTED_FILES, DEFAULT_MAX_SELECTED_FILES, 5000);
}

function maxShareFiles(env: Bindings) {
  return parsePositiveInt(env.MAX_SHARE_FILES, DEFAULT_MAX_SHARE_FILES, 1000);
}

function uploadChunkBytes(env: Bindings) {
  return parsePositiveInt(env.UPLOAD_CHUNK_BYTES, 16 * 1024 * 1024, 64 * 1024 * 1024);
}

function uploadLimits(env: Bindings) {
  return {
    maxFileBytes: maxFileBytes(env),
    chunkBytes: uploadChunkBytes(env),
  };
}

function apiRateLimit(env: Bindings) {
  return parsePositiveInt(env.API_RATE_LIMIT_PER_MINUTE, DEFAULT_API_RATE_LIMIT_PER_MINUTE, 10000);
}

function authRateLimit(env: Bindings) {
  return parsePositiveInt(env.AUTH_RATE_LIMIT_PER_MINUTE, DEFAULT_AUTH_RATE_LIMIT_PER_MINUTE, 10000);
}

function authIdentityRateLimit(env: Bindings) {
  return parsePositiveInt(env.AUTH_IDENTITY_RATE_LIMIT_PER_MINUTE, DEFAULT_AUTH_IDENTITY_RATE_LIMIT_PER_MINUTE, 1000);
}

function shareVerifyRateLimit(env: Bindings) {
  return parsePositiveInt(env.SHARE_VERIFY_RATE_LIMIT_PER_MINUTE, DEFAULT_SHARE_VERIFY_RATE_LIMIT_PER_MINUTE, 10000);
}

function truthyEnv(value: string | undefined) {
  return /^(1|true|yes|on)$/i.test(value?.trim() || "");
}

function requestHost(request: Request) {
  return request.headers.get("Host") || new URL(request.url).host;
}

function hostnameFromHost(host: string) {
  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    return host.split(":")[0];
  }
}

function isLocalHostname(hostname: string) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function requestClientKey(request: Request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

function authIdentityKey(value: string) {
  const normalized = value.trim().toLocaleLowerCase().replace(/[^a-z0-9_.-]+/g, "_").slice(0, 64);
  return normalized || "blank";
}

function rateLimitResponse() {
  return Response.json(
    { error: "请求过于频繁，请稍后再试" },
    {
      status: 429,
      headers: {
        "Cache-Control": "no-store",
        "Retry-After": "60",
      },
    },
  );
}

function consumeRateLimit(key: string, limit: number, windowMs = 60_000) {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (bucket.count >= limit) return false;
  bucket.count += 1;

  if (rateBuckets.size > 5000) {
    for (const [bucketKey, value] of rateBuckets) {
      if (value.resetAt <= now) rateBuckets.delete(bucketKey);
    }
  }

  return true;
}

function isCrossSiteSubresource(request: Request) {
  const site = request.headers.get("Sec-Fetch-Site");
  const mode = request.headers.get("Sec-Fetch-Mode");
  const dest = request.headers.get("Sec-Fetch-Dest");

  if (site !== "cross-site") return false;
  if (SAFE_METHODS.has(request.method) && mode === "navigate" && (dest === "document" || dest === "empty")) return false;
  return true;
}

function isSameOriginRequest(request: Request) {
  const expectedHost = requestHost(request);
  let sawOriginHeader = false;
  for (const headerName of ["Origin", "Referer"]) {
    const value = request.headers.get(headerName);
    if (!value) continue;
    sawOriginHeader = true;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    if (url.host !== expectedHost) return false;
    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalHostname(url.hostname))) {
      return false;
    }
  }

  if (sawOriginHeader) return true;
  if (request.headers.get("Sec-Fetch-Site") === "same-origin") return true;
  return isLocalRequest(request) && !request.headers.has("Sec-Fetch-Site");
}

async function hmacSha256Base64Url(secret: string, input: string) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(input))));
}

function sessionSecret(env: Bindings) {
  return env.CSRF_SECRET?.trim() || runtimeSessionSecret();
}

async function csrfTokenForSession(env: Bindings, session: AuthSession) {
  const secret = sessionSecret(env);
  return hmacSha256Base64Url(secret, `csrf:${session.name}:${session.role}:${session.csrfSeed}`);
}

async function signShareDownloadTicket(env: Bindings, payload: ShareDownloadTicketPayload) {
  const encoded = base64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacSha256Base64Url(sessionSecret(env), encoded);
  return `${encoded}.${signature}`;
}

async function verifyShareDownloadTicket(env: Bindings, value: string | null) {
  if (!value) return null;
  const [encoded, signature] = value.split(".");
  if (!encoded || !signature) return null;
  const expected = await hmacSha256Base64Url(sessionSecret(env), encoded);
  if (!timingSafeEqual(signature, expected)) return null;

  let payload: ShareDownloadTicketPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encoded)));
  } catch {
    return null;
  }

  if (typeof payload.code !== "string" || typeof payload.expiresAt !== "number" || typeof payload.nonce !== "string") {
    return null;
  }
  if (!Array.isArray(payload.allowedIds) || payload.allowedIds.some((id) => typeof id !== "string" || !isUuid(id))) return null;
  if (Date.now() > payload.expiresAt) return null;
  return payload;
}

function parseCookies(request: Request) {
  const cookies = new Map<string, string>();
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName) continue;
    cookies.set(rawName, rawValue.join("="));
  }
  return cookies;
}

async function createSessionCookieValue(env: Bindings, session: AuthSession) {
  const payload = base64Url(
    new TextEncoder().encode(
      JSON.stringify({ user: session.name, csrfSeed: session.csrfSeed || "", createdAt: Date.now() }),
    ),
  );
  const signature = await hmacSha256Base64Url(sessionSecret(env), payload);
  return `${payload}.${signature}`;
}

async function verifySessionCookie(request: Request, env: Bindings) {
  const value = parseCookies(request).get(SESSION_COOKIE);
  if (!value) return null;
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return null;
  const expected = await hmacSha256Base64Url(sessionSecret(env), payload);
  if (!timingSafeEqual(signature, expected)) return null;

  let data: { user?: unknown; csrfSeed?: unknown; createdAt?: unknown };
  try {
    data = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload)));
  } catch {
    return null;
  }
  if (typeof data.user !== "string" || typeof data.createdAt !== "number") return null;
  if (typeof data.csrfSeed !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(data.csrfSeed)) return null;
  if (Date.now() - data.createdAt > SESSION_MAX_AGE_SECONDS * 1000) return null;
  return {
    user: data.user,
    csrfSeed: data.csrfSeed,
  };
}

function sessionCookieHeader(value: string) {
  return `${SESSION_COOKIE}=${value}; Max-Age=${SESSION_MAX_AGE_SECONDS}; Path=/; HttpOnly; SameSite=Lax; Secure`;
}

function clearSessionCookieHeader() {
  return `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure`;
}

function safeResponseHeaders(nonce: string) {
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "media-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy": csp,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self), clipboard-write=(self)",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
  };
}

function parseAuthUsers(value: string | undefined) {
  const users: AuthUser[] = [];
  const seen = new Set<string>();

  for (const entry of (value || "").split(",")) {
    const [rawName, password = "", rawRole = "user"] = entry.split(":");
    const name = rawName?.trim();
    const role = rawRole.trim().toLowerCase() === "admin" ? "admin" : "user";

    if (!name || !password || !/^[A-Za-z0-9_.-]{1,64}$/.test(name) || seen.has(name)) continue;
    seen.add(name);
    users.push({ name, password, role, source: "env" });
  }

  return users;
}

function authUsers(env: Bindings) {
  return parseAuthUsers(env.AUTH_USERS);
}

async function allAuthUsers(env: Bindings, storage?: ObjectStorage) {
  const users = authUsers(env);
  const seen = new Set(users.map((user) => user.name));
  const objectStorage = storage || createObjectStorage(env);
  const credentials = await getUserPasswordCredentials(objectStorage).catch(() => ({} as UserPasswordCredentials));
  const accounts = userAccountsFromCredentials(credentials);

  for (const account of Object.values(accounts)) {
    if (seen.has(account.name)) continue;
    seen.add(account.name);
    users.push({ name: account.name, password: "", role: account.role, source: "registered" });
  }

  return users;
}

function timingSafeEqual(a: string, b: string) {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] || 0) ^ (right[index] || 0);
  }

  return diff === 0;
}

function unauthorizedResponse() {
  return Response.json(
    { error: "请先登录" },
    {
      status: 401,
      headers: {
        "Cache-Control": "no-store",
      },
    },
  );
}

async function sessionForUserName(userName: string, env: Bindings, storage: ObjectStorage, csrfSeed = randomToken(24)) {
  const users = await allAuthUsers(env, storage);
  const user = users.find((item) => item.name === userName);
  if (!user) return null;
  const profiles = await getUserProfiles(storage).catch(() => ({} as UserProfiles));
  const role = profiles[user.name]?.role || user.role;
  return { name: user.name, role, baseRole: user.role, configured: true, csrfSeed } satisfies AuthSession;
}

async function authenticateCredentials(
  userName: string,
  password: string,
  env: Bindings,
  storage: ObjectStorage,
  csrfSeed = randomToken(24),
) {
  const users = await allAuthUsers(env, storage);
  const user = users.find((item) => item.name === userName);
  if (!user) return null;

  const credentials = await getUserPasswordCredentials(storage).catch(() => ({} as UserPasswordCredentials));
  const credential = credentials[user.name];
  const passwordMatches = credential
    ? await verifyUserPasswordHash(user.name, credential.passwordHash, password)
    : user.source === "env" && timingSafeEqual(user.password, password);
  if (!passwordMatches) return null;

  const profiles = await getUserProfiles(storage).catch(() => ({} as UserProfiles));
  const role = profiles[user.name]?.role || user.role;
  return { name: user.name, role, baseRole: user.role, configured: true, csrfSeed } satisfies AuthSession;
}

function legacyBasicCredentials(request: Request) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) return null;
  let decoded = "";
  try {
    decoded = atob(header.slice(6));
  } catch {
    return null;
  }

  const separator = decoded.indexOf(":");
  if (separator < 0) return null;
  return {
    name: decoded.slice(0, separator),
    password: decoded.slice(separator + 1),
  };
}

function htmlUnauthorizedResponse(nonce: string, csrfToken: string) {
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="${csrfToken}">
<title>Cirrus Drive</title>
<style nonce="${nonce}">${styles}</style>
</head>
<body>${renderAuthShellHtml(nonce)}</body>
</html>`;
  return new Response(html, {
    status: 401,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function authenticate(request: Request, env: Bindings): Promise<AuthSession | null> {
  const storage = createObjectStorage(env);
  const configuredUsers = authUsers(env);
  const credentials = await getUserPasswordCredentials(storage).catch(() => ({} as UserPasswordCredentials));
  if (!configuredUsers.length && !Object.keys(credentials).length) {
    if (!truthyEnv(env.ALLOW_UNCONFIGURED_AUTH) && !isLocalRequest(request)) return null;
    return { name: "admin", role: "admin", baseRole: "admin", configured: false, csrfSeed: "unconfigured-local" };
  }

  const cookieSession = await verifySessionCookie(request, env);
  if (cookieSession) {
    const session = await sessionForUserName(cookieSession.user, env, storage, cookieSession.csrfSeed);
    if (session) return session;
  }

  const basic = legacyBasicCredentials(request);
  return basic ? authenticateCredentials(basic.name, basic.password, env, storage, "legacy-basic-auth") : null;
}

function isLocalRequest(request: Request) {
  return isLocalHostname(hostnameFromHost(requestHost(request)));
}

function fileMatchesVisibleTags(file: DriveFileMeta, tags: string[]) {
  const granted = new Set(tags.map((tag) => tag.toLocaleLowerCase()));
  return file.tags.some((tag) => granted.has(tag.toLocaleLowerCase()));
}

function canManageFile(session: AuthSession, file: DriveFileMeta) {
  return session.role === "admin" || file.owner === session.name;
}

function requireManageFile(session: AuthSession, file: DriveFileMeta | null) {
  if (!file) throw new AppError("文件不存在", 404);
  if (!canManageFile(session, file)) throw new AppError("无权操作该文件", 403);
  return file;
}

function requireAdmin(session: AuthSession) {
  if (session.role !== "admin") throw new AppError("需要管理员权限", 403);
}

async function visibleFiles(storage: ObjectStorage, session: AuthSession) {
  const files = await listFiles(storage);
  if (session.role === "admin") return files;

  const grants = await getUserTagGrants(storage);
  const profiles = await getUserProfiles(storage);
  const visibleTags = grants[session.name] || [];
  const visibleFileIds = new Set(profiles[session.name]?.visibleFileIds || []);

  return files.filter(
    (file) => file.owner === session.name || visibleFileIds.has(file.id) || fileMatchesVisibleTags(file, visibleTags),
  );
}

function fileExtension(name: string) {
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return "";
  return name.slice(dot + 1);
}

function matchesSearch(file: DriveFileMeta, query: string) {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return true;

  const haystack = [
    file.name,
    file.description,
    fileExtension(file.name),
    ...file.tags,
  ].join(" ").toLocaleLowerCase();

  return haystack.includes(normalized);
}

function matchesTag(file: DriveFileMeta, tag: string) {
  const normalized = tag.trim().toLocaleLowerCase();
  if (!normalized) return true;
  return file.tags.some((item) => item.toLocaleLowerCase() === normalized);
}

function filterFiles(files: DriveFileMeta[], search: string | undefined, tag: string | undefined) {
  return files.filter((file) => matchesSearch(file, search || "") && matchesTag(file, tag || ""));
}

function userNamesFromEnv(env: Bindings) {
  return authUsers(env)
    .filter((user) => user.role !== "admin")
    .map((user) => user.name);
}

function allUserNamesFromEnv(env: Bindings) {
  return authUsers(env).map((user) => user.name);
}

async function userNamesForAdmin(env: Bindings, storage: ObjectStorage) {
  return (await allAuthUsers(env, storage)).filter((user) => user.role !== "admin").map((user) => user.name);
}

async function allUserNames(env: Bindings, storage: ObjectStorage) {
  return (await allAuthUsers(env, storage)).map((user) => user.name);
}

function knownTags(files: DriveFileMeta[], grants: UserTagGrants) {
  const tags = new Map<string, string>();

  for (const file of files) {
    for (const tag of file.tags) {
      tags.set(tag.toLocaleLowerCase(), tag);
    }
  }

  for (const userTags of Object.values(grants)) {
    for (const tag of userTags) {
      tags.set(tag.toLocaleLowerCase(), tag);
    }
  }

  return Array.from(tags.values()).sort((a, b) => a.localeCompare(b, "zh-CN"));
}

function fileForClient(file: DriveFileMeta) {
  const { owner: _owner, ...publicFile } = file;
  return publicFile;
}

function fileForAdmin(file: DriveFileMeta) {
  return file;
}

function userProfileForClient(user: AuthUser, profiles: UserProfiles, currentUser: string) {
  const profile = profiles[user.name] || null;
  return {
    name: user.name,
    nickname: profile?.nickname || "",
    avatar: profile?.avatar || "",
    status: profile?.status || "",
    tags: profile?.tags || [],
    isFriend: profile?.friends.includes(currentUser) || profiles[currentUser]?.friends.includes(user.name) || false,
  };
}

function userSummary(user: AuthUser, profiles: UserProfiles, files: DriveFileMeta[], grants: UserTagGrants) {
  const profile = profiles[user.name] || null;
  const ownedCount = files.filter((file) => file.owner === user.name).length;
  const effectiveRole = profile?.role || user.role;

  return {
    name: user.name,
    nickname: profile?.nickname || "",
    avatar: profile?.avatar || "",
    status: profile?.status || "",
    baseRole: user.role,
    role: effectiveRole,
    tags: profile?.tags || [],
    visibleTags: grants[user.name] || [],
    friends: profile?.friends || [],
    visibleFileIds: profile?.visibleFileIds || [],
    notificationCount: profile?.notifications.length || 0,
    unreadNotificationCount: profile?.notifications.filter((notification) => !notification.readAt).length || 0,
    ownedCount,
    updatedAt: profile?.updatedAt || null,
  };
}

function messageForClient(message: DirectMessage, files: Map<string, DriveFileMeta>) {
  return {
    ...message,
    files: message.fileIds
      .map((id) => files.get(id))
      .filter((file): file is DriveFileMeta => Boolean(file))
      .map(fileForClient),
  };
}

function renderAuthShellHtml(nonce: string) {
  return `<main class="app-shell auth-required-shell" data-app="auth" data-role="" data-user="" data-auth-required="true">
  <aside class="side-rail">
    <a class="brand" href="/" aria-label="Cirrus Drive">
      <span class="brand-mark">C</span>
      <span><strong>Cirrus</strong><small>Cloud Drive</small></span>
    </a>
    <div class="storage-card">
      <span>需要登录</span>
      <strong>欢迎回来</strong>
      <small>登录或注册后继续</small>
    </div>
  </aside>
  <section class="workspace">
    <header class="topbar">
      <div>
        <p class="eyebrow">Personal Cloud</p>
        <h1>文件</h1>
      </div>
    </header>
    <section class="file-surface" aria-label="文件列表">
      <div class="empty-state"><strong>请先登录</strong><span>登录后会显示你的文件和好友消息。</span></div>
    </section>
  </section>
  <dialog id="auth-dialog" class="modal auth-modal">
    <form method="dialog" class="modal-panel" id="auth-form">
      <header>
        <h2 id="auth-title">登录</h2>
      </header>
      <label><span>用户名</span><input id="auth-username" autocomplete="username" autofocus /></label>
      <label><span>密码</span><input id="auth-password" type="password" autocomplete="current-password" /></label>
      <label id="auth-confirm-row" hidden><span>确认密码</span><input id="auth-confirm-password" type="password" autocomplete="new-password" /></label>
      <output id="auth-status"></output>
      <footer>
        <button id="auth-mode-button" type="button">注册账号</button>
        <button id="auth-submit-button" value="default">登录</button>
      </footer>
    </form>
  </dialog>
  <script nonce="${nonce}">${authClientScript}</script>
</main>`;
}

async function incrementDownloads(storage: ObjectStorage, files: DriveFileMeta[], waitUntil?: (promise: Promise<unknown>) => void) {
  const promise = Promise.all(files.map((file) => incrementDownload(storage, file.id))).then(() => undefined);
  if (waitUntil) {
    waitUntil(promise);
    return;
  }
  await promise;
}

async function zipResponse(
  storage: ObjectStorage,
  files: DriveFileMeta[],
  archiveName: string,
  waitUntil?: (promise: Promise<unknown>) => void,
) {
  if (!files.length) throw new AppError("文件不存在", 404);
  const sources = files.map((file) => ({
    name: file.name,
    size: file.size,
    uploadedAt: file.uploadedAt,
    body: async () => {
      const object = await storage.get(objectKey(file.id));
      return object?.body || null;
    },
  }));

  await incrementDownloads(storage, files, waitUntil);

  return new Response(createStoredZipStream(sources), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": attachmentName(archiveName),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function singleFileResponse(
  storage: ObjectStorage,
  file: DriveFileMeta,
  waitUntil?: (promise: Promise<unknown>) => void,
) {
  const object = await storage.get(objectKey(file.id));
  if (!object?.body) throw new AppError("文件不存在", 404);

  await incrementDownloads(storage, [file], waitUntil);

  return new Response(object.body, {
    headers: {
      "Content-Type": file.contentType || "application/octet-stream",
      "Content-Length": String(file.size),
      "Content-Disposition": attachmentName(file.name),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function filesForShareDownload(storage: ObjectStorage, share: ShareRecord, ids: string[] | null, maxIds: number) {
  const requestedIds = ids ? Array.from(new Set(ids.slice(0, maxIds + 1))) : null;
  if (requestedIds && requestedIds.length > maxIds) throw new AppError("选择的文件过多", 413);
  const files = requestedIds ? await resolveShareFilesByIds(storage, share, requestedIds) : await resolveShareFiles(storage, share);
  if (!files.length) throw new AppError("文件不存在", 404);
  return files;
}

async function shareDownloadResponse(
  storage: ObjectStorage,
  share: ShareRecord,
  ids: string[] | null,
  maxIds: number,
  waitUntil?: (promise: Promise<unknown>) => void,
) {
  const files = await filesForShareDownload(storage, share, ids, maxIds);

  if (files.length === 1) {
    return singleFileResponse(storage, files[0], waitUntil);
  }

  return zipResponse(storage, files, `Cirrus-share-${share.code}.zip`, waitUntil);
}

app.use(
  jsxRenderer(({ children }, c) => {
    const nonce = c.get("nonce");
    const csrfToken = c.get("csrfToken");

    return (
      <html lang="zh-CN">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <meta name="csrf-token" content={csrfToken} />
          <title>Cirrus Drive</title>
          <style nonce={nonce} dangerouslySetInnerHTML={{ __html: styles }} />
        </head>
        <body>{children}</body>
      </html>
    );
  }),
);

app.use("*", async (c, next) => {
  const nonce = randomToken();
  c.set("nonce", nonce);
  c.set("csrfToken", "");

  try {
    await next();
  } finally {
    const headers = safeResponseHeaders(nonce);
    for (const [name, value] of Object.entries(headers)) {
      c.header(name, value);
    }
  }
});

app.use("*", async (c, next) => {
  if (isCrossSiteSubresource(c.req.raw)) {
    return errorResponse("跨站请求被拒绝", 403);
  }

  if (SAFE_METHODS.has(c.req.method)) {
    await next();
    return;
  }

  if (!isSameOriginRequest(c.req.raw)) {
    return errorResponse("请求来源无效", 403);
  }

  await next();
});

app.use("/api/*", async (c, next) => {
  const path = new URL(c.req.url).pathname;
  const clientKey = requestClientKey(c.req.raw);
  if (!consumeRateLimit(`api:${clientKey}`, apiRateLimit(c.env))) {
    return rateLimitResponse();
  }

  const isPublicShareRead = c.req.method === "GET" && /^\/api\/shares\/[^/]+$/.test(path);
  const isPublicShareVerify = c.req.method === "POST" && /^\/api\/shares\/[^/]+\/verify$/.test(path);
  const isPublicShareDownload =
    (c.req.method === "POST" || c.req.method === "GET") && /^\/api\/shares\/[^/]+\/download$/.test(path);
  const isPublicShareDownloadTicket =
    c.req.method === "POST" && /^\/api\/shares\/[^/]+\/download-ticket$/.test(path);
  const isAuthEndpoint = c.req.method === "POST" && /^\/api\/auth\/(?:login|register|logout)$/.test(path);
  if (isAuthEndpoint && !consumeRateLimit(`auth:${clientKey}`, authRateLimit(c.env))) {
    return rateLimitResponse();
  }
  if (isPublicShareVerify && !consumeRateLimit(`share-verify:${clientKey}:${path}`, shareVerifyRateLimit(c.env))) {
    return rateLimitResponse();
  }
  if (
    (isPublicShareDownload || isPublicShareDownloadTicket) &&
    !consumeRateLimit(`share-download:${clientKey}:${path}`, shareVerifyRateLimit(c.env))
  ) {
    return rateLimitResponse();
  }
  if (
    isPublicShareRead ||
    isPublicShareVerify ||
    isPublicShareDownload ||
    isPublicShareDownloadTicket ||
    isAuthEndpoint
  ) {
    await next();
    return;
  }

  if (!consumeRateLimit(`auth:${clientKey}`, authRateLimit(c.env))) {
    return rateLimitResponse();
  }
  const session = await authenticate(c.req.raw, c.env);
  if (!session) return unauthorizedResponse();
  c.set("session", session);

  const csrfToken = await csrfTokenForSession(c.env, session);
  c.set("csrfToken", csrfToken);
  if (!SAFE_METHODS.has(c.req.method) && c.req.header("X-CSRF-Token") !== csrfToken) {
    return errorResponse("CSRF token 无效", 403);
  }

  await next();
});

app.get("/", async (c) => {
  if (!consumeRateLimit(`auth:${requestClientKey(c.req.raw)}`, authRateLimit(c.env))) {
    return rateLimitResponse();
  }
  const session = await authenticate(c.req.raw, c.env);
  if (!session) return htmlUnauthorizedResponse(c.get("nonce"), "");
  c.set("csrfToken", await csrfTokenForSession(c.env, session));
  return c.render(
    <DriveApp storageName={storageLabel(c.env)} session={session} nonce={c.get("nonce")} limits={uploadLimits(c.env)} />,
  );
});

app.get("/admin", async (c) => {
  if (!consumeRateLimit(`auth:${requestClientKey(c.req.raw)}`, authRateLimit(c.env))) {
    return rateLimitResponse();
  }
  const session = await authenticate(c.req.raw, c.env);
  if (!session) return unauthorizedResponse();
  if (session.role !== "admin") return errorResponse("需要管理员权限", 403);
  c.set("csrfToken", await csrfTokenForSession(c.env, session));
  return c.render(<AdminApp nonce={c.get("nonce")} />);
});

app.get("/s/:code", (c) => {
  const code = c.req.param("code");
  return c.render(<ShareApp code={code} nonce={c.get("nonce")} />);
});

app.post("/api/auth/login", async (c) => {
  try {
    const body = await jsonBody<{ username?: unknown; password?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const username = typeof body.username === "string" ? body.username : "";
    const password = typeof body.password === "string" ? body.password : "";
    const identityKey = authIdentityKey(username);
    if (!consumeRateLimit(`auth-identity:${requestClientKey(c.req.raw)}:${identityKey}`, authIdentityRateLimit(c.env))) {
      return rateLimitResponse();
    }
    const storage = createObjectStorage(c.env);
    const session = await authenticateCredentials(username, password, c.env, storage);
    if (!session) throw new AppError("用户名或密码不正确", 401);

    const cookie = await createSessionCookieValue(c.env, session);
    c.header("Set-Cookie", sessionCookieHeader(cookie));
    return c.json({ user: { name: session.name, role: session.role }, csrfToken: await csrfTokenForSession(c.env, session) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/auth/register", async (c) => {
  try {
    const body = await jsonBody<{ username?: unknown; password?: unknown; confirmPassword?: unknown }>(
      c.req.raw,
      maxJsonBytes(c.env),
    );
    const username = typeof body.username === "string" ? body.username : "";
    const password = typeof body.password === "string" ? body.password : "";
    const confirmPassword = typeof body.confirmPassword === "string" ? body.confirmPassword : "";
    const identityKey = authIdentityKey(username);
    if (!consumeRateLimit(`auth-identity:${requestClientKey(c.req.raw)}:${identityKey}`, authIdentityRateLimit(c.env))) {
      return rateLimitResponse();
    }
    if (password !== confirmPassword) throw new AppError("两次输入的密码不一致");

    const storage = createObjectStorage(c.env);
    const existing = authUsers(c.env).map((user) => user.name);
    const account = await createRegisteredUser(storage, username, password, existing);
    const session = await sessionForUserName(account.name, c.env, storage, randomToken(24));
    if (!session) throw new AppError("注册失败", 500);

    const cookie = await createSessionCookieValue(c.env, session);
    c.header("Set-Cookie", sessionCookieHeader(cookie));
    return c.json({ user: { name: session.name, role: session.role }, csrfToken: await csrfTokenForSession(c.env, session) }, 201);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/auth/logout", (c) => {
  c.header("Set-Cookie", clearSessionCookieHeader());
  return c.json({ ok: true });
});

app.get("/api/files", async (c) => {
  const storage = createObjectStorage(c.env);
  const files = filterFiles(await visibleFiles(storage, c.get("session")), c.req.query("q"), c.req.query("tag"));
  return c.json({ files: files.map(fileForClient) });
});

app.get("/api/me", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const profiles = await getUserProfiles(storage);
    const session = c.get("session");
    const user = (await allAuthUsers(c.env, storage)).find((item) => item.name === session.name) || {
      name: session.name,
      password: "",
      role: session.baseRole,
      source: "registered" as const,
    };

    return c.json({
      user: {
        ...userProfileForClient(user, profiles, session.name),
        role: session.role,
        baseRole: session.baseRole,
        configured: session.configured,
      },
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/me/profile", async (c) => {
  try {
    const body = await jsonBody<{
      nickname?: unknown;
      avatar?: unknown;
      status?: unknown;
      currentPassword?: unknown;
      newPassword?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const allowedUsers = await allUserNames(c.env, storage);
    const profile = await updateOwnUserProfile(storage, c.get("session").name, {
      nickname: body.nickname,
      avatar: body.avatar,
      status: body.status,
      allowedUsers: allowedUsers.length ? allowedUsers : undefined,
    });

    let passwordChanged = false;
    if (body.newPassword !== undefined && String(body.newPassword || "").trim()) {
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
      const currentUser = (await allAuthUsers(c.env, storage)).find((user) => user.name === c.get("session").name);
      if (!currentUser) throw new AppError("用户不存在", 404);

      const credentials = await getUserPasswordCredentials(storage);
      const credential = credentials[currentUser.name];
      const verified = credential
        ? await verifyUserPasswordHash(currentUser.name, credential.passwordHash, currentPassword)
        : timingSafeEqual(currentUser.password, currentPassword);
      if (!verified) throw new AppError("当前密码不正确", 403);

      await updateUserPassword(storage, currentUser.name, newPassword, allowedUsers.length ? allowedUsers : undefined);
      passwordChanged = true;
    }

    return c.json({ profile, passwordChanged });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/users/search", async (c) => {
  try {
    const query = (c.req.query("q") || "").trim().toLocaleLowerCase();
    if (!query) return c.json({ users: [] });

    const storage = createObjectStorage(c.env);
    const profiles = await getUserProfiles(storage);
    const currentUser = c.get("session").name;
    const users = (await allAuthUsers(c.env, storage))
      .filter((user) => user.name !== currentUser)
      .filter((user) => {
        const profile = profiles[user.name];
        const haystack = [
          user.name,
          profile?.nickname || "",
          ...(profile?.tags || []),
        ].join(" ").toLocaleLowerCase();
        return haystack.includes(query);
      })
      .slice(0, 30)
      .map((user) => userProfileForClient(user, profiles, currentUser));

    return c.json({ users });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/friends", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const profiles = await getUserProfiles(storage);
    const users = new Map((await allAuthUsers(c.env, storage)).map((user) => [user.name, user]));
    const current = profiles[c.get("session").name];
    const friends = (current?.friends || [])
      .map((name) => users.get(name))
      .filter(Boolean)
      .map((user) => userProfileForClient(user as AuthUser, profiles, c.get("session").name));
    return c.json({ friends });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/friends/:user", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const allowedUsers = await allUserNames(c.env, storage);
    const profiles = await addFriend(storage, c.get("session").name, c.req.param("user"), allowedUsers);
    const target = (await allAuthUsers(c.env, storage)).find((user) => user.name === c.req.param("user"));
    if (!target) throw new AppError("用户不存在", 404);
    return c.json({ friend: userProfileForClient(target, profiles, c.get("session").name) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.delete("/api/friends/:user", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    await removeFriend(storage, c.get("session").name, c.req.param("user"), await allUserNames(c.env, storage));
    return c.json({ ok: true });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/messages/:user", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const messages = await getDirectMessages(storage, c.get("session").name, c.req.param("user"), await allUserNames(c.env, storage));
    const allowedFiles = new Map((await visibleFiles(storage, c.get("session"))).map((file) => [file.id, file]));
    return c.json({ messages: messages.map((message) => messageForClient(message, allowedFiles)) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/messages/:user", async (c) => {
  try {
    const body = await jsonBody<{ message?: unknown; fileIds?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const fileIds = Array.isArray(body.fileIds)
      ? body.fileIds.filter((id): id is string => typeof id === "string" && isUuid(id))
      : [];
    const profiles = await getUserProfiles(storage);
    const targetUser = c.req.param("user");
    if (!profiles[c.get("session").name]?.friends.includes(targetUser)) {
      throw new AppError("只能给好友发送私信", 403);
    }
    if (fileIds.length) {
      const allowed = new Set((await visibleFiles(storage, c.get("session"))).map((file) => file.id));
      if (fileIds.some((id) => !allowed.has(id))) throw new AppError("无权分享所选文件", 403);
      await updateUserProfiles(storage, {
        users: [c.req.param("user")],
        visibleFileIds: fileIds,
        visibleFileMode: "add",
        allowedUsers: await allUserNames(c.env, storage),
      });
    }

    const message = await sendDirectMessage(storage, {
      from: c.get("session").name,
      to: c.req.param("user"),
      message: body.message,
      fileIds,
      allowedUsers: await allUserNames(c.env, storage),
    });
    const files = new Map((await visibleFiles(storage, c.get("session"))).map((file) => [file.id, file]));
    return c.json({ message: messageForClient(message, files) }, 201);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/notifications", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const profiles = await getUserProfiles(storage);
    const profile = profiles[c.get("session").name];
    return c.json({ notifications: profile?.notifications.slice().reverse() || [] });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/notifications/read", async (c) => {
  try {
    const body = await jsonBody<{ ids?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const notifications = await markUserNotificationsRead(
      storage,
      c.get("session").name,
      Array.isArray(body.ids) ? body.ids.filter((id): id is string => typeof id === "string") : undefined,
    );
    return c.json({ notifications: notifications.slice().reverse() });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/files", async (c) => {
  try {
    const form = await c.req.formData();
    const expiresAt = parseOptionalDate(form.get("expiresAt"));
    const files = (form.getAll("files") as unknown[]).filter(isUploadedFile);

    if (!files.length) {
      throw new AppError("请选择要上传的文件");
    }
    const perFileLimit = maxFileBytes(c.env);
    if (files.some((file) => file.size > perFileLimit)) {
      throw new AppError("单个文件过大", 413);
    }

    const storage = createObjectStorage(c.env);
    const session = c.get("session");
    const fallbackDescription = cleanDescription(form.get("description"));
    const fallbackTags = cleanTags(form.get("tags"));
    const uploaded = await Promise.all(
      files.map((file, index) => {
        const description = cleanDescription(form.get(`description:${index}`)) || fallbackDescription;
        const tags = cleanTags(form.get(`tags:${index}`));
        return createFileFromUpload(storage, file, expiresAt, description, tags.length ? tags : fallbackTags, session.name);
      }),
    );

    return c.json({ files: uploaded.map(fileForClient) }, 201);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/uploads/multipart", async (c) => {
  try {
    const body = await jsonBody<{
      name?: unknown;
      size?: unknown;
      contentType?: unknown;
      description?: unknown;
      tags?: unknown;
      expiresAt?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));
    const size = typeof body.size === "number" && Number.isFinite(body.size) ? body.size : -1;
    if (size < 0) throw new AppError("文件大小无效");
    if (size > maxFileBytes(c.env)) throw new AppError("单个文件过大", 413);

    const storage = createObjectStorage(c.env);
    if (!storage.createMultipartUpload) throw new AppError("当前存储后端不支持分片上传", 501);

    const id = crypto.randomUUID();
    const contentType = typeof body.contentType === "string" && body.contentType.trim() ? body.contentType : "application/octet-stream";
    const upload = await storage.createMultipartUpload(objectKey(id), { contentType });
    return c.json({
      id,
      uploadId: upload.uploadId,
      partSize: uploadChunkBytes(c.env),
      file: {
        name: typeof body.name === "string" ? body.name : "",
        size,
        contentType,
        description: cleanDescription(body.description),
        tags: cleanTags(body.tags),
        expiresAt: parseOptionalDate(body.expiresAt),
      },
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/uploads/direct", async (c) => {
  try {
    const body = await jsonBody<{
      name?: unknown;
      size?: unknown;
      contentType?: unknown;
      description?: unknown;
      tags?: unknown;
      expiresAt?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));
    const size = typeof body.size === "number" && Number.isFinite(body.size) ? body.size : -1;
    if (size < 0) throw new AppError("文件大小无效");
    if (size > maxFileBytes(c.env)) throw new AppError("单个文件过大", 413);

    if (storageBackend(c.env) !== "s3") throw new AppError("当前存储后端不支持直传", 501);
    const storage = createObjectStorage(c.env);
    if (!storage.createDirectUploadUrl) throw new AppError("当前存储后端不支持直传", 501);

    const id = crypto.randomUUID();
    const contentType = typeof body.contentType === "string" && body.contentType.trim() ? body.contentType : "application/octet-stream";
    const upload = await storage.createDirectUploadUrl(objectKey(id), { contentType });
    return c.json({
      id,
      upload,
      file: {
        name: typeof body.name === "string" ? body.name : "",
        size,
        contentType,
        description: cleanDescription(body.description),
        tags: cleanTags(body.tags),
        expiresAt: parseOptionalDate(body.expiresAt),
      },
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/uploads/direct/:id/complete", async (c) => {
  try {
    const id = c.req.param("id");
    if (!isUuid(id)) throw new AppError("上传参数无效");
    const body = await jsonBody<{
      name?: unknown;
      size?: unknown;
      contentType?: unknown;
      expiresAt?: unknown;
      description?: unknown;
      tags?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));
    const size = typeof body.size === "number" && Number.isFinite(body.size) ? body.size : -1;
    if (size < 0) throw new AppError("文件大小无效");
    if (size > maxFileBytes(c.env)) throw new AppError("单个文件过大", 413);

    const storage = createObjectStorage(c.env);
    const file = await createFileFromCompletedUpload(storage, {
      id,
      name: typeof body.name === "string" ? body.name : "",
      size,
      contentType: typeof body.contentType === "string" ? body.contentType : "",
      expiresAt: parseOptionalDate(body.expiresAt),
      description: cleanDescription(body.description),
      tags: cleanTags(body.tags),
      owner: c.get("session").name,
    });
    return c.json({ file: fileForClient(file) }, 201);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.put("/api/uploads/multipart/:id/:uploadId/:partNumber", async (c) => {
  try {
    const id = c.req.param("id");
    const uploadId = c.req.param("uploadId");
    const partNumber = Number(c.req.param("partNumber"));
    if (!isUuid(id) || !uploadId || !Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
      throw new AppError("分片参数无效");
    }

    const contentLength = parseContentLength(c.req.header("Content-Length") || null);
    const chunkLimit = uploadChunkBytes(c.env) + 1024 * 1024;
    if (contentLength !== null && contentLength > chunkLimit) {
      throw new AppError("分片过大", 413);
    }

    const storage = createObjectStorage(c.env);
    if (!storage.uploadMultipartPart) throw new AppError("当前存储后端不支持分片上传", 501);

    const part = await storage.uploadMultipartPart({ key: objectKey(id), uploadId }, partNumber, await c.req.arrayBuffer());
    return c.json(part);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/uploads/multipart/:id/:uploadId/complete", async (c) => {
  try {
    const id = c.req.param("id");
    const uploadId = c.req.param("uploadId");
    if (!isUuid(id) || !uploadId) throw new AppError("分片参数无效");
    const body = await jsonBody<{
      name?: unknown;
      size?: unknown;
      contentType?: unknown;
      expiresAt?: unknown;
      description?: unknown;
      tags?: unknown;
      parts?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));
    const size = typeof body.size === "number" && Number.isFinite(body.size) ? body.size : -1;
    if (size < 0) throw new AppError("文件大小无效");
    if (size > maxFileBytes(c.env)) throw new AppError("单个文件过大", 413);

    const parts = Array.isArray(body.parts)
      ? body.parts
          .map((part) => {
            const value = part && typeof part === "object" ? (part as { partNumber?: unknown; etag?: unknown }) : {};
            return {
              partNumber: typeof value.partNumber === "number" ? value.partNumber : 0,
              etag: typeof value.etag === "string" ? value.etag : "",
            };
          })
          .filter((part) => Number.isSafeInteger(part.partNumber) && part.partNumber > 0 && part.etag)
      : [];
    if (!parts.length) throw new AppError("缺少上传分片");

    const storage = createObjectStorage(c.env);
    if (!storage.completeMultipartUpload) throw new AppError("当前存储后端不支持分片上传", 501);
    await storage.completeMultipartUpload({ key: objectKey(id), uploadId }, parts);

    const file = await createFileFromCompletedUpload(storage, {
      id,
      name: typeof body.name === "string" ? body.name : "",
      size,
      contentType: typeof body.contentType === "string" ? body.contentType : "",
      expiresAt: parseOptionalDate(body.expiresAt),
      description: cleanDescription(body.description),
      tags: cleanTags(body.tags),
      owner: c.get("session").name,
    });
    return c.json({ file: fileForClient(file) }, 201);
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.delete("/api/uploads/multipart/:id/:uploadId", async (c) => {
  try {
    const id = c.req.param("id");
    const uploadId = c.req.param("uploadId");
    if (!isUuid(id) || !uploadId) throw new AppError("分片参数无效");
    const storage = createObjectStorage(c.env);
    await storage.abortMultipartUpload?.({ key: objectKey(id), uploadId });
    return c.json({ ok: true });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/files/:id/description", async (c) => {
  try {
    const body = await jsonBody<{ description?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    requireManageFile(c.get("session"), await getActiveFileMeta(storage, c.req.param("id")));
    const file = await updateFileDescription(storage, c.req.param("id"), cleanDescription(body.description));
    return c.json({ file: fileForClient(file) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/files/:id/tags", async (c) => {
  try {
    const body = await jsonBody<{ tags?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    requireManageFile(c.get("session"), await getActiveFileMeta(storage, c.req.param("id")));
    const file = await updateFileTags(storage, c.req.param("id"), cleanTags(body.tags));
    return c.json({ file: fileForClient(file) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/files/:id", async (c) => {
  try {
    const body = await jsonBody<{ name?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    if (typeof body.name !== "string" || !body.name.trim()) {
      throw new AppError("请输入文件名");
    }
    const storage = createObjectStorage(c.env);
    requireManageFile(c.get("session"), await getActiveFileMeta(storage, c.req.param("id")));
    const file = await renameFile(storage, c.req.param("id"), body.name);
    return c.json({ file: fileForClient(file) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.delete("/api/files", async (c) => {
  try {
    const body = await jsonBody<{ ids?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const ids = idsFromValue(body.ids, maxSelectedFiles(c.env));
    const storage = createObjectStorage(c.env);
    const session = c.get("session");
    const files = await Promise.all(ids.map((id) => getActiveFileMeta(storage, id)));
    for (const file of files) {
      requireManageFile(session, file);
    }
    await Promise.all(ids.map((id) => deleteDriveFile(storage, id)));
    return c.json({ ok: true });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/files/copy", async (c) => {
  try {
    const body = await jsonBody<{ ids?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const ids = idsFromValue(body.ids, maxSelectedFiles(c.env));
    const storage = createObjectStorage(c.env);
    const session = c.get("session");
    const sources = await Promise.all(ids.map((id) => getActiveFileMeta(storage, id)));
    for (const file of sources) {
      requireManageFile(session, file);
    }
    const files = await copyFiles(storage, ids, session.name);
    return c.json({ files: files.map(fileForClient) });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/files/:id/download", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const file = await getActiveFileMeta(storage, c.req.param("id"));
    if (!file) throw new AppError("文件不存在", 404);
    if (!(await visibleFiles(storage, c.get("session"))).some((item) => item.id === file.id)) {
      throw new AppError("文件不存在", 404);
    }
    return singleFileResponse(storage, file, c.executionCtx.waitUntil.bind(c.executionCtx));
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/files/download", async (c) => {
  try {
    const body = await jsonBody<{ ids?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const ids = idsFromValue(body.ids, maxSelectedFiles(c.env));
    const storage = createObjectStorage(c.env);
    const allowed = new Map((await visibleFiles(storage, c.get("session"))).map((file) => [file.id, file]));
    const files = ids.map((id) => allowed.get(id)).filter(Boolean) as DriveFileMeta[];
    if (files.length !== ids.length) throw new AppError("文件不存在或无权下载", 404);

    if (files.length === 1) {
      return singleFileResponse(storage, files[0], c.executionCtx.waitUntil.bind(c.executionCtx));
    }

    return zipResponse(
      storage,
      files,
      `Cirrus-${new Date().toISOString().slice(0, 10)}.zip`,
      c.executionCtx.waitUntil.bind(c.executionCtx),
    );
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/shares", async (c) => {
  try {
    const body = await jsonBody<{
      fileIds?: unknown;
      code?: unknown;
      password?: unknown;
      expiresAt?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));

    const input: CreateShareInput = {
      fileIds: idsFromValue(body.fileIds, maxShareFiles(c.env)),
      code: typeof body.code === "string" && body.code.trim() ? body.code : undefined,
      password: typeof body.password === "string" && body.password.trim() ? body.password : undefined,
      expiresAt: parseOptionalDate(body.expiresAt),
    };

    const storage = createObjectStorage(c.env);
    const allowed = new Set((await visibleFiles(storage, c.get("session"))).map((file) => file.id));
    const unauthorized = input.fileIds.some((id) => !allowed.has(id));
    if (unauthorized) throw new AppError("无权分享所选文件", 403);
    const share = await createShare(storage, input);
    return c.json({
      share: {
        code: share.code,
        fileIds: share.fileIds,
        expiresAt: share.expiresAt,
        hasPassword: Boolean(share.passwordHash),
        url: new URL(`/s/${share.code}`, c.req.url).toString(),
      },
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/shares/:code", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const share = await getShare(storage, c.req.param("code"));
    if (!share) throw new AppError("分享不存在或已过期", 404);

    if (share.passwordHash) {
      return c.json({
        locked: true,
        code: share.code,
        expiresAt: share.expiresAt,
      });
    }

    const files = await resolveShareFiles(storage, share);
    return c.json({
      locked: false,
      code: share.code,
      expiresAt: share.expiresAt,
      files: files.map(fileForClient),
      downloadTicket: await signShareDownloadTicket(c.env, {
        code: share.code,
        allowedIds: files.map((file) => file.id),
        expiresAt: Date.now() + SHARE_DOWNLOAD_TICKET_SECONDS * 1000,
        nonce: randomToken(12),
      }),
      downloadTicketExpiresIn: SHARE_DOWNLOAD_TICKET_SECONDS,
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/shares/:code/verify", async (c) => {
  try {
    const body = await jsonBody<{ password?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const share = await getShare(storage, c.req.param("code"));
    if (!share) throw new AppError("分享不存在或已过期", 404);

    const password = typeof body.password === "string" ? body.password : undefined;
    const verified = await verifySharePassword(share, password);
    if (!verified) throw new AppError("密码不正确", 403);

    const files = await resolveShareFiles(storage, share);
    return c.json({
      locked: false,
      code: share.code,
      expiresAt: share.expiresAt,
      files: files.map(fileForClient),
      downloadTicket: await signShareDownloadTicket(c.env, {
        code: share.code,
        allowedIds: files.map((file) => file.id),
        expiresAt: Date.now() + SHARE_DOWNLOAD_TICKET_SECONDS * 1000,
        nonce: randomToken(12),
      }),
      downloadTicketExpiresIn: SHARE_DOWNLOAD_TICKET_SECONDS,
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/shares/:code/download", async (c) => {
  try {
    const body = await jsonBody<{ password?: unknown; ids?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const share = await getShare(storage, c.req.param("code"));
    if (!share) throw new AppError("分享不存在或已过期", 404);

    const password = typeof body.password === "string" ? body.password : undefined;
    const verified = await verifySharePassword(share, password);
    if (!verified) throw new AppError("密码不正确", 403);

    return shareDownloadResponse(
      storage,
      share,
      body.ids ? idsFromValue(body.ids, maxShareFiles(c.env)) : null,
      maxShareFiles(c.env),
      c.executionCtx.waitUntil.bind(c.executionCtx),
    );
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/shares/:code/download-ticket", async (c) => {
  try {
    const body = await jsonBody<{ password?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const share = await getShare(storage, c.req.param("code"));
    if (!share) throw new AppError("分享不存在或已过期", 404);

    const password = typeof body.password === "string" ? body.password : undefined;
    const verified = await verifySharePassword(share, password);
    if (!verified) throw new AppError("密码不正确", 403);
    const files = await resolveShareFiles(storage, share);
    if (!files.length) throw new AppError("文件不存在", 404);

    return c.json({
      ticket: await signShareDownloadTicket(c.env, {
        code: share.code,
        allowedIds: files.map((file) => file.id),
        expiresAt: Date.now() + SHARE_DOWNLOAD_TICKET_SECONDS * 1000,
        nonce: randomToken(12),
      }),
      expiresIn: SHARE_DOWNLOAD_TICKET_SECONDS,
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/shares/:code/download", async (c) => {
  try {
    const storage = createObjectStorage(c.env);
    const share = await getShare(storage, c.req.param("code"));
    if (!share) throw new AppError("分享不存在或已过期", 404);

    const ticket = await verifyShareDownloadTicket(c.env, c.req.query("ticket") || null);
    if (!ticket || ticket.code !== share.code) throw new AppError("下载链接已失效，请重新点击下载", 403);
    const selectedIds = c.req.queries("id") || [];
    const requestedIds = selectedIds.length ? idsFromValue(selectedIds, maxShareFiles(c.env)) : ticket.allowedIds;
    const allowedIds = new Set(ticket.allowedIds);
    if (requestedIds.some((id) => !allowedIds.has(id))) throw new AppError("下载链接已失效，请重新点击下载", 403);

    return shareDownloadResponse(storage, share, requestedIds, maxShareFiles(c.env), c.executionCtx.waitUntil.bind(c.executionCtx));
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/admin/permissions", async (c) => {
  try {
    requireAdmin(c.get("session"));
    const storage = createObjectStorage(c.env);
    const files = await listFiles(storage);
    const grants = await getUserTagGrants(storage);

    return c.json({
      users: await userNamesForAdmin(c.env, storage),
      grants,
      tags: knownTags(files, grants),
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.patch("/api/admin/permissions/:user", async (c) => {
  try {
    requireAdmin(c.get("session"));
    const body = await jsonBody<{ tags?: unknown }>(c.req.raw, maxJsonBytes(c.env));
    const storage = createObjectStorage(c.env);
    const tags = await setUserVisibleTags(storage, c.req.param("user"), cleanTags(body.tags), {
      allowedUsers: await userNamesForAdmin(c.env, storage),
    });

    return c.json({ user: c.req.param("user"), tags });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.get("/api/admin/overview", async (c) => {
  try {
    requireAdmin(c.get("session"));
    const storage = createObjectStorage(c.env);
    const files = await listFiles(storage);
    const grants = await getUserTagGrants(storage);
    const profiles = await getUserProfiles(storage);
    const users = await allAuthUsers(c.env, storage);

    return c.json({
      users: users.map((user) => userSummary(user, profiles, files, grants)),
      files: files.map(fileForAdmin),
      grants,
      tags: knownTags(files, grants),
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

app.post("/api/admin/users/batch", async (c) => {
  try {
    requireAdmin(c.get("session"));
    const body = await jsonBody<{
      users?: unknown;
      role?: unknown;
      tags?: unknown;
      tagMode?: unknown;
      visibleTags?: unknown;
      visibleTagMode?: unknown;
      visibleFileIds?: unknown;
      visibleFileMode?: unknown;
      notification?: unknown;
    }>(c.req.raw, maxJsonBytes(c.env));

    const storage = createObjectStorage(c.env);
    const allowedUsers = await allUserNames(c.env, storage);
    const users = Array.isArray(body.users) ? body.users.filter((user): user is string => typeof user === "string") : [];
    const role: UserRole | null | undefined =
      body.role === "admin" || body.role === "user" || body.role === null ? body.role : undefined;
    const tagMode: MergeMode =
      body.tagMode === "add" || body.tagMode === "remove" || body.tagMode === "replace" ? body.tagMode : "replace";
    const visibleFileMode: MergeMode =
      body.visibleFileMode === "add" || body.visibleFileMode === "remove" || body.visibleFileMode === "replace"
        ? body.visibleFileMode
        : "replace";
    const visibleTagMode: MergeMode =
      body.visibleTagMode === "add" || body.visibleTagMode === "remove" || body.visibleTagMode === "replace"
        ? body.visibleTagMode
        : "replace";
    const shouldUpdateProfiles =
      role !== undefined ||
      body.tags !== undefined ||
      body.visibleFileIds !== undefined ||
      (body.notification !== undefined && body.notification !== null);
    const profileInput = {
      users,
      role,
      ...(body.tags !== undefined ? { tags: cleanTags(body.tags) } : {}),
      tagMode,
      ...(body.visibleFileIds !== undefined
        ? {
            visibleFileIds: Array.isArray(body.visibleFileIds)
              ? body.visibleFileIds.filter((id): id is string => typeof id === "string" && isUuid(id))
              : [],
          }
        : {}),
      visibleFileMode,
      notification:
        body.notification && typeof body.notification === "object"
          ? { ...(body.notification as object), from: c.get("session").name }
          : null,
      allowedUsers,
    };
    const profiles = shouldUpdateProfiles ? await updateUserProfiles(storage, profileInput) : await getUserProfiles(storage);

    const grants =
      body.visibleTags !== undefined
        ? await updateUserTagGrants(storage, {
            users,
            tags: cleanTags(body.visibleTags),
            mode: visibleTagMode,
            allowedUsers,
          })
        : await getUserTagGrants(storage);

    const files = await listFiles(storage);
    return c.json({
      users: (await allAuthUsers(c.env, storage)).map((user) => userSummary(user, profiles, files, grants)),
      grants,
    });
  } catch (error) {
    const { message, status } = jsonError(error);
    return errorResponse(message, status);
  }
});

function DriveApp({
  storageName,
  session,
  nonce,
  limits,
}: {
  storageName: string;
  session: AuthSession;
  nonce: string;
  limits: ReturnType<typeof uploadLimits>;
}) {
  return (
    <main
      class="app-shell"
      data-app="drive"
      data-role={session.role}
      data-user={session.name}
      data-auth-configured={String(session.configured)}
      data-max-file-bytes={String(limits.maxFileBytes)}
      data-upload-chunk-bytes={String(limits.chunkBytes)}
    >
      <aside class="side-rail">
        <a class="brand" href="/" aria-label="Cirrus Drive">
          <span class="brand-mark">C</span>
          <span>
            <strong>Cirrus</strong>
            <small>Cloud Drive</small>
          </span>
        </a>
        <nav class="nav-stack" aria-label="主导航">
          <button class="nav-item active" type="button" data-view="files">
            <span>云端文件</span>
          </button>
          <button class="nav-item" type="button" data-action="notifications">
            <span>通知</span>
            <small id="notification-count"></small>
          </button>
          <button class="nav-item" type="button" data-action="profile">
            <span>账号设置</span>
          </button>
          <button class="nav-item" type="button" data-action="friends">
            <span>好友私信</span>
          </button>
          <button class="nav-item" type="button" data-action="logout">
            <span>退出登录</span>
          </button>
          <button class="nav-item" type="button" data-action="refresh">
            <span>刷新列表</span>
          </button>
          <button class="nav-item" type="button" data-action="paste" disabled>
            <span>粘贴</span>
          </button>
          {session.role === "admin" ? (
            <a class="nav-item nav-link" href="/admin">
              <span>权限管理</span>
            </a>
          ) : null}
        </nav>
        <div class="storage-card">
          <span>{storageName}</span>
          <strong id="storage-count">0 个文件</strong>
          <small id="user-badge">{session.role === "admin" ? `管理员 ${session.name}` : session.name}</small>
        </div>
      </aside>

      <section class="workspace">
        <header class="topbar">
          <div>
            <p class="eyebrow">Personal Cloud</p>
            <h1>文件</h1>
          </div>
          <button class="upload-button" type="button" data-action="open-upload">上传</button>
        </header>

        <div class="command-bar" role="toolbar" aria-label="文件操作">
          <input id="file-search" type="search" placeholder="搜索文件名、标签、描述、扩展名" autocomplete="off" />
          <button type="button" id="clear-filter-button" hidden>清除筛选</button>
          <button type="button" data-action="download-selected" disabled>下载</button>
          <button type="button" data-action="share-selected" disabled>分享</button>
          <button type="button" data-action="copy-selected" disabled>复制</button>
          <button type="button" data-action="cut-selected" disabled>剪切</button>
          <button type="button" data-action="rename-selected" disabled>改名</button>
          <button type="button" data-action="delete-selected" disabled>删除</button>
          <span id="selection-summary">未选择文件</span>
        </div>

        <section class="file-surface" id="file-surface" aria-label="文件列表">
          <div class="table-head" aria-hidden="true">
            <span>名称</span>
            <span>描述</span>
            <span>标签</span>
            <span>上传时间</span>
            <span>最后下载</span>
            <span>下载次数</span>
          </div>
          <div id="file-list" class="file-list"></div>
          <div id="empty-state" class="empty-state" hidden>
            <strong>还没有文件</strong>
            <span>上传后会直接出现在这里。</span>
          </div>
          <div id="selection-box" class="selection-box" hidden></div>
        </section>
      </section>

      <div id="context-menu" class="context-menu" hidden>
        <button type="button" data-menu-action="rename">改名</button>
        <button type="button" data-menu-action="description">修改描述</button>
        <button type="button" data-menu-action="tags">修改标签</button>
        <button type="button" data-menu-action="download">下载</button>
        <button type="button" data-menu-action="select">选择</button>
        <button type="button" data-menu-action="copy">复制</button>
        <button type="button" data-menu-action="cut">剪切</button>
        <button type="button" data-menu-action="share">分享</button>
      </div>

      <dialog id="notification-dialog" class="modal notification-modal">
        <form method="dialog" class="modal-panel">
          <header>
            <h2>通知</h2>
            <button type="button" data-action="close-dialog" aria-label="关闭">×</button>
          </header>
          <div id="notification-list" class="notification-list"></div>
          <footer>
            <span id="notification-status">暂无通知</span>
            <button id="mark-notifications-read" value="default" type="button">全部标为已读</button>
          </footer>
        </form>
      </dialog>

      <dialog id="profile-dialog" class="modal profile-modal">
        <form method="dialog" class="modal-panel" id="profile-form">
          <header>
            <h2>账号设置</h2>
            <button type="button" data-action="close-dialog" aria-label="关闭">×</button>
          </header>
          <div class="profile-preview">
            <span id="profile-avatar-preview" class="avatar-preview"></span>
            <span>
              <strong id="profile-preview-name">{session.name}</strong>
              <small>用户名不可修改</small>
            </span>
          </div>
          <label>
            <span>昵称</span>
            <input id="profile-nickname" maxLength={32} autocomplete="nickname" placeholder="设置唯一昵称" />
          </label>
          <label>
            <span>状态</span>
            <input id="profile-status-text" maxLength={80} autocomplete="off" placeholder="忙碌、在线、休假中..." />
          </label>
          <label>
            <span>头像</span>
            <input id="profile-avatar" type="file" accept="image/png,image/jpeg,image/webp,image/gif" />
          </label>
          <label>
            <span>当前密码</span>
            <input id="profile-current-password" type="password" autocomplete="current-password" placeholder="修改密码时填写" />
          </label>
          <label>
            <span>新密码</span>
            <input id="profile-new-password" type="password" autocomplete="new-password" placeholder="至少 6 位，留空则不修改" />
          </label>
          <label>
            <span>确认新密码</span>
            <input id="profile-confirm-password" type="password" autocomplete="new-password" placeholder="再次输入新密码" />
          </label>
          <output id="profile-status"></output>
          <footer>
            <button type="button" data-action="close-dialog">取消</button>
            <button id="save-profile-button" value="default">保存资料</button>
          </footer>
        </form>
      </dialog>

      <dialog id="friends-dialog" class="modal friends-modal">
        <form method="dialog" class="modal-panel" id="friends-form">
          <header>
            <h2>好友私信</h2>
            <button type="button" data-action="close-dialog" aria-label="关闭">×</button>
          </header>
          <div class="friends-layout">
            <section class="friends-sidebar">
              <input id="friend-search" type="search" placeholder="搜索用户名、昵称、标签" autocomplete="off" />
              <div id="friend-search-results" class="compact-list"></div>
              <div id="friend-list" class="compact-list"></div>
            </section>
            <section class="chat-panel">
              <div id="chat-heading" class="chat-heading">请选择好友</div>
              <div id="message-list" class="message-list"></div>
              <label>
                <span>私信</span>
                <textarea id="message-input" rows={3} placeholder="输入私信内容"></textarea>
              </label>
              <label>
                <span>附带文件</span>
                <select id="message-file-select" multiple size={5}></select>
              </label>
              <footer>
                <span id="friends-status">未选择好友</span>
                <button id="send-message-button" type="submit" disabled>发送</button>
              </footer>
            </section>
          </div>
        </form>
      </dialog>

      <dialog id="upload-dialog" class="modal upload-modal">
        <form method="dialog" class="modal-panel" id="upload-form">
          <header>
            <h2>上传文件</h2>
            <button type="button" data-action="close-dialog" aria-label="关闭">×</button>
          </header>
          <label class="file-picker">
            <span>选择文件</span>
            <input id="file-input" name="files" type="file" multiple />
          </label>
          <div id="upload-file-list" class="upload-file-list"></div>
          <label>
            <span>存留时间</span>
            <select id="retention-select" aria-label="存留时间">
              <option value="">永久保存</option>
              <option value="1">保留 1 天</option>
              <option value="7">保留 7 天</option>
              <option value="30">保留 30 天</option>
              <option value="custom">自定义</option>
            </select>
          </label>
          <input id="custom-expiry" type="datetime-local" aria-label="自定义存留到期时间" hidden />
          <div id="upload-progress-wrap" class="upload-progress" hidden>
            <progress id="upload-progress" max="100" value="0"></progress>
            <output id="upload-progress-text">等待上传</output>
          </div>
          <footer>
            <button type="button" data-action="close-dialog">取消</button>
            <button id="confirm-upload-button" type="submit" value="default" disabled>确认上传</button>
          </footer>
        </form>
      </dialog>

      {session.role === "admin" ? (
        <dialog id="permission-dialog" class="modal permission-modal">
          <form method="dialog" class="modal-panel" id="permission-form">
            <header>
              <h2>权限管理</h2>
              <button type="button" data-action="close-dialog" aria-label="关闭">×</button>
            </header>
            <label>
              <span>用户</span>
              <select id="permission-user"></select>
            </label>
            <label>
              <span>可见标签</span>
              <input id="permission-tags" placeholder="多个标签用逗号分隔" autocomplete="off" />
            </label>
            <div id="known-tags" class="tag-suggestions"></div>
            <footer>
              <button type="button" data-action="close-dialog">取消</button>
              <button id="save-permission-button" value="default">保存权限</button>
            </footer>
          </form>
        </dialog>
      ) : null}

      <dialog id="share-dialog" class="modal">
        <form method="dialog" class="modal-panel" id="share-form">
          <header>
            <h2>创建分享</h2>
          </header>
          <label>
            <span>分享码</span>
            <input id="share-code" placeholder="留空自动生成" autocomplete="off" />
          </label>
          <label>
            <span>密码</span>
            <input id="share-password" placeholder="留空免密码" autocomplete="new-password" />
          </label>
          <label>
            <span>有效期</span>
            <input id="share-expiry" type="datetime-local" />
          </label>
          <label>
            <span>分享链接</span>
            <div class="share-link-row">
              <input id="share-output" readonly aria-label="分享链接" />
              <button id="copy-share-link-button" type="button" disabled>复制</button>
            </div>
          </label>
          <footer>
            <button type="button" data-action="close-dialog">取消</button>
            <button id="create-share-button" value="default">生成分享</button>
          </footer>
        </form>
      </dialog>

      <script nonce={nonce} dangerouslySetInnerHTML={{ __html: clientScript }} />
    </main>
  );
}

function AdminApp({ nonce }: { nonce: string }) {
  return (
    <main class="admin-shell" data-app="admin">
      <aside class="side-rail">
        <a class="brand" href="/" aria-label="Cirrus Drive">
          <span class="brand-mark">C</span>
          <span>
            <strong>Cirrus</strong>
            <small>Admin</small>
          </span>
        </a>
        <nav class="nav-stack" aria-label="管理导航">
          <a class="nav-item nav-link" href="/">
            <span>返回文件</span>
          </a>
          <button class="nav-item" type="button" data-action="admin-refresh">
            <span>刷新管理数据</span>
          </button>
        </nav>
        <div class="storage-card">
          <span>Admin Console</span>
          <strong id="admin-count">0 个用户</strong>
        </div>
      </aside>

      <section class="workspace">
        <header class="topbar">
          <div>
            <p class="eyebrow">Administration</p>
            <h1>用户管理</h1>
          </div>
        </header>

        <div class="admin-layout">
          <section class="file-surface admin-panel" aria-label="用户列表">
            <div class="table-head user-head" aria-hidden="true">
              <span>用户</span>
              <span>角色</span>
              <span>用户标签</span>
              <span>可见标签</span>
              <span>可见文件</span>
              <span>通知</span>
            </div>
            <div id="admin-user-list" class="file-list"></div>
          </section>

          <form id="admin-batch-form" class="modal-panel admin-tools">
            <h2>批量控制</h2>
            <label>
              <span>角色</span>
              <select id="admin-role">
                <option value="">不修改</option>
                <option value="user">普通用户</option>
                <option value="admin">管理员</option>
                <option value="clear">恢复配置角色</option>
              </select>
            </label>
            <label>
              <span>用户标签</span>
              <input id="admin-user-tags" placeholder="多个标签用逗号分隔" autocomplete="off" />
            </label>
            <div class="tag-suggestions" id="admin-user-known-tags"></div>
            <label>
              <span>标签模式</span>
              <select id="admin-tag-mode">
                <option value="replace">替换</option>
                <option value="add">追加</option>
                <option value="remove">移除</option>
              </select>
            </label>
            <label class="inline-check">
              <input id="admin-clear-user-tags" type="checkbox" />
              <span>清空用户标签</span>
            </label>
            <label>
              <span>可见标签</span>
              <input id="admin-visible-tags" placeholder="用户可见的文件标签" autocomplete="off" />
            </label>
            <div class="tag-suggestions" id="admin-visible-known-tags"></div>
            <label>
              <span>可见标签模式</span>
              <select id="admin-visible-tag-mode">
                <option value="replace">替换</option>
                <option value="add">追加</option>
                <option value="remove">移除</option>
              </select>
            </label>
            <label class="inline-check">
              <input id="admin-clear-visible-tags" type="checkbox" />
              <span>清空可见标签</span>
            </label>
            <label>
              <span>可见文件</span>
              <select id="admin-visible-files" multiple size={8}></select>
            </label>
            <label>
              <span>文件模式</span>
              <select id="admin-file-mode">
                <option value="replace">替换</option>
                <option value="add">追加</option>
                <option value="remove">移除</option>
              </select>
            </label>
            <label class="inline-check">
              <input id="admin-clear-visible-files" type="checkbox" />
              <span>清空指定可见文件</span>
            </label>
            <label>
              <span>通知标题</span>
              <input id="admin-notice-title" placeholder="留空则不发送通知" autocomplete="off" />
            </label>
            <label>
              <span>通知内容</span>
              <textarea id="admin-notice-message" rows={4} placeholder="发送给所选用户"></textarea>
            </label>
            <footer>
              <span id="admin-status">请选择用户</span>
              <button id="admin-apply-button">应用到所选用户</button>
            </footer>
          </form>
        </div>
      </section>

      <script nonce={nonce} dangerouslySetInnerHTML={{ __html: adminClientScript }} />
    </main>
  );
}

function ShareApp({ code, nonce }: { code: string; nonce: string }) {
  return (
    <main class="share-shell" data-app="share" data-share-code={code}>
      <section class="share-panel">
        <a class="brand" href="/" aria-label="Cirrus Drive">
          <span class="brand-mark">C</span>
          <span>
            <strong>Cirrus</strong>
            <small>Shared files</small>
          </span>
        </a>
        <span id="share-expiry-note"></span>
        <form id="share-password-form" class="password-card" hidden>
          <input id="share-password-input" type="password" placeholder="输入分享密码" autocomplete="current-password" />
          <button>解锁</button>
        </form>
        <div class="command-bar">
          <button type="button" data-action="share-download-all" disabled>下载全部</button>
          <span id="share-status">正在读取分享...</span>
        </div>
        <div id="share-file-list" class="file-list shared"></div>
      </section>
      <div id="share-context-menu" class="context-menu" hidden>
        <button type="button" data-share-menu-action="download">下载</button>
      </div>
      <script nonce={nonce} dangerouslySetInnerHTML={{ __html: shareClientScript }} />
    </main>
  );
}

const styles = String.raw`
:root {
  color-scheme: light dark;
  --bg: #eef4f7;
  --bg-2: #f8fbfb;
  --text: #172326;
  --muted: #627174;
  --line: rgba(49, 74, 79, 0.18);
  --glass: rgba(255, 255, 255, 0.58);
  --glass-strong: rgba(255, 255, 255, 0.76);
  --accent: #067a88;
  --accent-2: #b9572a;
  --danger: #b42318;
  --shadow: 0 24px 70px rgba(28, 54, 61, 0.18);
  --radius: 8px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #071111;
    --bg-2: #101b1c;
    --text: #edf6f5;
    --muted: #a4b4b4;
    --line: rgba(214, 239, 239, 0.16);
    --glass: rgba(19, 31, 33, 0.62);
    --glass-strong: rgba(26, 42, 45, 0.78);
    --accent: #46c3c8;
    --accent-2: #f08b57;
    --danger: #ff8d80;
    --shadow: 0 24px 80px rgba(0, 0, 0, 0.34);
  }
}

* {
  box-sizing: border-box;
}

[hidden] {
  display: none !important;
}

body {
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(circle at 18% 12%, rgba(6, 122, 136, 0.18), transparent 34%),
    radial-gradient(circle at 82% 18%, rgba(185, 87, 42, 0.16), transparent 28%),
    linear-gradient(135deg, var(--bg), var(--bg-2));
  letter-spacing: 0;
}

button,
input,
textarea,
select {
  font: inherit;
}

button {
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--text);
  background: var(--glass-strong);
  cursor: pointer;
  backdrop-filter: blur(18px) saturate(1.3);
  transition:
    transform 160ms ease,
    border-color 160ms ease,
    background 160ms ease;
}

button:hover:not(:disabled) {
  transform: translateY(-1px);
  border-color: color-mix(in srgb, var(--accent), var(--line) 35%);
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.46;
}

input,
textarea,
select {
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--text);
  background: var(--glass);
  padding: 0 12px;
  outline: none;
  backdrop-filter: blur(18px) saturate(1.3);
}

input:focus,
textarea:focus,
select:focus {
  border-color: var(--accent);
}

textarea {
  min-height: 84px;
  padding: 10px 12px;
  resize: vertical;
}

.app-shell {
  display: grid;
  min-height: 100vh;
  grid-template-columns: 252px minmax(0, 1fr);
}

.side-rail {
  position: sticky;
  top: 0;
  display: flex;
  height: 100vh;
  flex-direction: column;
  gap: 22px;
  padding: 22px;
  border-right: 1px solid var(--line);
  background: color-mix(in srgb, var(--glass), transparent 10%);
  backdrop-filter: blur(28px) saturate(1.35);
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  color: inherit;
  text-decoration: none;
}

.brand-mark {
  display: grid;
  width: 42px;
  height: 42px;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--accent), var(--line) 42%);
  border-radius: 8px;
  color: white;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  font-weight: 800;
  box-shadow: 0 16px 32px rgba(6, 122, 136, 0.22);
}

.brand strong,
.brand small {
  display: block;
}

.brand small {
  color: var(--muted);
}

.nav-stack {
  display: grid;
  gap: 8px;
}

.nav-item {
  justify-content: flex-start;
  width: 100%;
  padding: 0 12px;
  text-align: left;
}

.nav-link {
  display: inline-flex;
  min-height: 38px;
  align-items: center;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: inherit;
  background: var(--glass-strong);
  text-decoration: none;
}

.nav-item.active {
  color: white;
  border-color: transparent;
  background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent), #0f2f35 32%));
}

.storage-card {
  margin-top: auto;
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
  box-shadow: var(--shadow);
}

.storage-card span,
.storage-card strong {
  display: block;
}

.storage-card small {
  display: block;
  margin-top: 4px;
  color: var(--muted);
  font-size: 0.78rem;
}

.storage-card span,
.eyebrow,
.table-head,
#selection-summary,
#share-status,
#share-expiry-note,
#notification-count {
  color: var(--muted);
  font-size: 0.86rem;
}

.workspace {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 16px;
  padding: 24px clamp(16px, 3vw, 38px);
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.eyebrow {
  margin: 0 0 3px;
  text-transform: uppercase;
}

h1,
h2 {
  margin: 0;
  line-height: 1.05;
  letter-spacing: 0;
}

h1 {
  font-size: clamp(2rem, 4vw, 3.7rem);
}

h2 {
  font-size: 1.2rem;
}

.upload-button {
  display: inline-grid;
  min-height: 38px;
  place-items: center;
  border: 1px solid transparent;
  border-radius: var(--radius);
  color: white;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  cursor: pointer;
  padding: 0 16px;
  box-shadow: 0 18px 40px rgba(6, 122, 136, 0.18);
}

.command-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 54px;
  padding: 8px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
  box-shadow: var(--shadow);
  backdrop-filter: blur(24px) saturate(1.4);
  overflow-x: auto;
}

.command-bar button {
  flex: 0 0 auto;
  padding: 0 12px;
}

.command-bar input {
  flex: 1 1 280px;
  min-width: 220px;
}

.command-bar span {
  margin-left: auto;
  white-space: nowrap;
}

.file-surface {
  position: relative;
  min-height: 420px;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--glass), transparent 8%);
  box-shadow: var(--shadow);
  backdrop-filter: blur(30px) saturate(1.35);
}

.table-head,
.file-row {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) minmax(170px, 0.65fr) minmax(150px, 0.54fr) minmax(145px, 0.42fr) minmax(145px, 0.42fr) 96px;
  align-items: center;
  gap: 12px;
}

.table-head {
  position: sticky;
  top: 0;
  z-index: 1;
  min-height: 46px;
  padding: 0 18px;
  border-bottom: 1px solid var(--line);
  background: color-mix(in srgb, var(--glass-strong), transparent 3%);
  backdrop-filter: blur(24px) saturate(1.35);
}

.file-list {
  display: grid;
  align-content: start;
  max-height: calc(100vh - 214px);
  overflow: auto;
}

.file-row {
  position: relative;
  min-height: 58px;
  padding: 0 18px;
  border: 0;
  border-bottom: 1px solid color-mix(in srgb, var(--line), transparent 35%);
  border-radius: 0;
  color: inherit;
  cursor: pointer;
  font: inherit;
  background: transparent;
  text-align: left;
  transform: none;
}

.file-row:hover,
.file-row.selected {
  background: color-mix(in srgb, var(--accent), transparent 87%);
}

.file-row.cut {
  opacity: 0.52;
}

.file-name {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.file-icon {
  display: grid;
  flex: 0 0 auto;
  width: 32px;
  height: 32px;
  place-items: center;
  border-radius: 8px;
  color: white;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  font-size: 0.78rem;
  font-weight: 800;
}

.file-title {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-size {
  display: block;
  color: var(--muted);
  font-size: 0.82rem;
}

.file-description {
  overflow: hidden;
  color: var(--muted);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-tags,
.tag-suggestions {
  display: flex;
  min-width: 0;
  flex-wrap: wrap;
  gap: 6px;
}

.tag-chip {
  min-height: 24px;
  border: 1px solid color-mix(in srgb, var(--accent), var(--line) 50%);
  border-radius: 999px;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent), transparent 88%);
  padding: 2px 8px;
  font-size: 0.78rem;
  line-height: 1.35;
}

.tag-chip[role="button"],
button.tag-chip {
  cursor: pointer;
}

.tag-empty {
  color: var(--muted);
  font-size: 0.86rem;
}

.empty-state {
  display: grid;
  min-height: 320px;
  place-content: center;
  gap: 8px;
  color: var(--muted);
  text-align: center;
}

.empty-state strong {
  color: var(--text);
  font-size: 1.15rem;
}

.selection-box {
  position: absolute;
  z-index: 10;
  border: 1px solid var(--accent);
  background: color-mix(in srgb, var(--accent), transparent 80%);
  pointer-events: none;
}

.context-menu {
  position: fixed;
  z-index: 30;
  display: grid;
  min-width: 180px;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass-strong);
  box-shadow: var(--shadow);
  backdrop-filter: blur(30px) saturate(1.4);
}

.context-menu button {
  min-height: 40px;
  border: 0;
  border-radius: 0;
  background: transparent;
  text-align: left;
  padding: 0 14px;
}

.modal {
  width: min(460px, calc(100vw - 28px));
  border: 1px solid var(--line);
  border-radius: 8px;
  color: var(--text);
  background: var(--glass-strong);
  box-shadow: var(--shadow);
  backdrop-filter: blur(32px) saturate(1.45);
}

.modal::backdrop {
  background: rgba(0, 0, 0, 0.38);
  backdrop-filter: blur(8px);
}

.modal-panel {
  display: grid;
  gap: 14px;
}

.modal-panel header,
.modal-panel footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.modal-panel label {
  display: grid;
  gap: 6px;
  color: var(--muted);
}

.modal-panel .inline-check {
  display: flex;
  min-height: 30px;
  align-items: center;
  gap: 8px;
}

.inline-check input {
  width: auto;
  min-height: auto;
}

.modal-panel input {
  width: 100%;
}

.modal-panel textarea,
.modal-panel select {
  width: 100%;
}

.modal-panel output {
  min-height: 22px;
  color: var(--accent);
  word-break: break-all;
}

.upload-modal {
  width: min(720px, calc(100vw - 28px));
}

.file-picker {
  display: grid;
  gap: 8px;
  border: 1px dashed var(--line);
  border-radius: var(--radius);
  padding: 12px;
  background: var(--glass);
}

.file-picker input[type="file"] {
  display: block;
  min-height: 44px;
  padding: 4px 12px;
  line-height: 34px;
}

.file-picker input[type="file"]::file-selector-button {
  min-height: 34px;
  margin: 0 8px 0 0;
}

.upload-file-list {
  display: grid;
  max-height: min(38vh, 340px);
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
}

.upload-file-row {
  display: grid;
  grid-template-columns: minmax(150px, 0.65fr) minmax(190px, 1fr) minmax(170px, 0.8fr);
  align-items: start;
  gap: 10px;
  padding: 10px 12px;
  border-bottom: 1px solid color-mix(in srgb, var(--line), transparent 35%);
}

.upload-file-row:last-child {
  border-bottom: 0;
}

.upload-file-meta {
  min-width: 0;
  padding-top: 2px;
}

.upload-file-meta strong,
.upload-file-meta small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.upload-file-meta small {
  color: var(--muted);
  font-size: 0.82rem;
}

.upload-file-row textarea,
.upload-file-row input {
  height: 44px;
  min-height: 44px;
  padding: 9px 12px;
  line-height: 24px;
}

.upload-file-row textarea {
  resize: none;
}

.upload-progress {
  display: grid;
  gap: 6px;
}

.upload-progress progress {
  width: 100%;
  height: 12px;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: color-mix(in srgb, var(--line), transparent 45%);
}

.upload-progress progress::-webkit-progress-bar {
  background: color-mix(in srgb, var(--line), transparent 45%);
}

.upload-progress progress::-webkit-progress-value {
  background: linear-gradient(90deg, var(--accent), var(--accent-2));
}

.upload-progress progress::-moz-progress-bar {
  background: linear-gradient(90deg, var(--accent), var(--accent-2));
}

.upload-progress output {
  min-height: 18px;
  color: var(--muted);
  font-size: 0.88rem;
}

.permission-modal {
  width: min(560px, calc(100vw - 28px));
}

.notification-modal {
  width: min(620px, calc(100vw - 28px));
}

.profile-modal {
  width: min(520px, calc(100vw - 28px));
}

.auth-modal {
  width: min(420px, calc(100vw - 28px));
}

.friends-modal {
  width: min(980px, calc(100vw - 28px));
}

.auth-required-shell .file-surface {
  min-height: 360px;
}

.profile-preview {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
}

.avatar-preview,
.avatar {
  display: grid;
  flex: 0 0 auto;
  width: 40px;
  height: 40px;
  place-items: center;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--accent), var(--line) 42%);
  border-radius: 50%;
  color: white;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  font-size: 0.9rem;
  font-weight: 800;
}

.avatar img,
.avatar-preview img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.notification-list {
  display: grid;
  max-height: min(54vh, 420px);
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
}

.friends-layout {
  display: grid;
  grid-template-columns: minmax(220px, 300px) minmax(0, 1fr);
  gap: 14px;
  min-height: 560px;
}

.friends-sidebar,
.chat-panel {
  display: grid;
  align-content: start;
  gap: 10px;
  min-width: 0;
}

.compact-list,
.message-list {
  display: grid;
  align-content: start;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
}

.compact-list {
  max-height: 210px;
}

.compact-user {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  min-height: 56px;
  padding: 8px;
  border: 0;
  border-bottom: 1px solid color-mix(in srgb, var(--line), transparent 35%);
  border-radius: 0;
  background: transparent;
  text-align: left;
}

.compact-user:hover,
.compact-user.active {
  background: color-mix(in srgb, var(--accent), transparent 88%);
}

.compact-user strong,
.compact-user small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chat-heading {
  min-height: 38px;
  display: flex;
  align-items: center;
  color: var(--muted);
}

.message-list {
  min-height: 230px;
  max-height: 260px;
  padding: 8px;
  gap: 8px;
}

.message-item {
  display: grid;
  gap: 4px;
  max-width: 78%;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass-strong);
}

.message-item.own {
  justify-self: end;
  border-color: color-mix(in srgb, var(--accent), var(--line) 42%);
  background: color-mix(in srgb, var(--accent), transparent 86%);
}

.message-item p {
  margin: 0;
  word-break: break-word;
}

.message-files {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.notification-item {
  display: grid;
  gap: 6px;
  padding: 12px;
  border-bottom: 1px solid color-mix(in srgb, var(--line), transparent 35%);
}

.notification-item:last-child {
  border-bottom: 0;
}

.notification-item.unread {
  background: color-mix(in srgb, var(--accent), transparent 90%);
}

.notification-item header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.notification-item strong,
.notification-item span {
  min-width: 0;
}

.notification-item p {
  margin: 0;
  color: var(--muted);
  word-break: break-word;
}

.notification-item small {
  color: var(--muted);
}

.tag-suggestions {
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
}

.share-shell {
  display: grid;
  min-height: 100vh;
  place-items: center;
  padding: 24px;
}

.share-panel {
  display: grid;
  width: min(920px, 100%);
  gap: 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
  padding: clamp(18px, 4vw, 34px);
  box-shadow: var(--shadow);
  backdrop-filter: blur(30px) saturate(1.4);
}

.password-card {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
}

.share-link-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
}

.file-list.shared {
  max-height: 54vh;
  border: 1px solid var(--line);
  border-radius: var(--radius);
}

.admin-shell {
  display: grid;
  min-height: 100vh;
  grid-template-columns: 252px minmax(0, 1fr);
}

.admin-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(300px, 380px);
  gap: 16px;
  align-items: start;
}

.admin-panel {
  min-height: 620px;
}

.user-head,
.user-row {
  grid-template-columns: minmax(150px, 0.9fr) 110px minmax(150px, 0.75fr) minmax(150px, 0.75fr) 112px 112px;
}

.user-row {
  display: grid;
  align-items: center;
  gap: 12px;
  min-height: 64px;
  padding: 10px 18px;
  border-bottom: 1px solid color-mix(in srgb, var(--line), transparent 35%);
}

.user-cell {
  min-width: 0;
}

.user-cell strong,
.user-cell small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.admin-tools {
  position: sticky;
  top: 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--glass);
  padding: 14px;
  box-shadow: var(--shadow);
  backdrop-filter: blur(24px) saturate(1.35);
}

.admin-tools footer {
  align-items: center;
}

.admin-tools footer span {
  color: var(--muted);
  font-size: 0.86rem;
}

@media (max-width: 860px) {
  .app-shell,
  .admin-shell {
    display: block;
  }

  .side-rail {
    position: static;
    height: auto;
    flex-direction: row;
    align-items: center;
    padding: 14px;
    overflow-x: auto;
  }

  .nav-stack {
    display: flex;
    min-width: max-content;
  }

  .storage-card {
    margin: 0 0 0 auto;
    min-width: 140px;
  }

  .workspace {
    padding: 16px;
  }

  .topbar {
    align-items: stretch;
    flex-direction: column;
  }

  .table-head {
    display: none;
  }

  .file-list {
    max-height: none;
  }

  .file-row {
    grid-template-columns: 1fr auto;
    grid-template-areas:
      "name count"
      "description description"
      "tags tags"
      "uploaded uploaded"
      "downloaded downloaded";
    gap: 4px 12px;
    min-height: 122px;
    padding: 12px;
  }

  .file-row > :nth-child(1) {
    grid-area: name;
  }

  .file-row > :nth-child(2) {
    grid-area: description;
  }

  .file-row > :nth-child(3) {
    grid-area: tags;
  }

  .file-row > :nth-child(4) {
    grid-area: uploaded;
  }

  .file-row > :nth-child(5) {
    grid-area: downloaded;
  }

  .file-row > :nth-child(6) {
    grid-area: count;
    text-align: right;
  }

  .admin-layout {
    grid-template-columns: 1fr;
  }

  .admin-tools {
    position: static;
  }

  .user-head {
    display: none;
  }

  .user-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 560px) {
  .side-rail {
    display: grid;
    grid-template-columns: 1fr;
  }

  .brand {
    width: 100%;
  }

  .storage-card {
    margin: 0;
  }

  .command-bar {
    align-items: stretch;
    flex-wrap: wrap;
  }

  .command-bar span {
    margin-left: 0;
  }

  .password-card {
    grid-template-columns: 1fr;
  }

  .upload-file-row {
    grid-template-columns: 1fr;
  }

  .friends-layout {
    grid-template-columns: 1fr;
    min-height: 0;
  }

  .message-item {
    max-width: 100%;
  }
}
`;

const clientScript = String.raw`
(() => {
  const state = {
    files: [],
    selected: new Set(),
    clipboard: null,
    contextId: null,
    dragging: null,
    query: "",
    tag: "",
    me: null,
    friends: [],
    friendResults: [],
    activeFriend: ""
  };

  const SAFE_WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const appRoot = document.querySelector("[data-app='drive']");
  const uploadLimits = {
    maxFileBytes: Number(appRoot?.dataset.maxFileBytes || 0),
    chunkBytes: Number(appRoot?.dataset.uploadChunkBytes || 0)
  };
  const isAdmin = appRoot?.dataset.role === "admin";
  const list = document.getElementById("file-list");
  const surface = document.getElementById("file-surface");
  const empty = document.getElementById("empty-state");
  const menu = document.getElementById("context-menu");
  const summary = document.getElementById("selection-summary");
  const storageCount = document.getElementById("storage-count");
  const searchInput = document.getElementById("file-search");
  const clearFilterButton = document.getElementById("clear-filter-button");
  const uploadDialog = document.getElementById("upload-dialog");
  const uploadForm = document.getElementById("upload-form");
  const fileInput = document.getElementById("file-input");
  const uploadFileList = document.getElementById("upload-file-list");
  const confirmUploadButton = document.getElementById("confirm-upload-button");
  const uploadProgressWrap = document.getElementById("upload-progress-wrap");
  const uploadProgress = document.getElementById("upload-progress");
  const uploadProgressText = document.getElementById("upload-progress-text");
  const notificationButton = document.querySelector('[data-action="notifications"]');
  const notificationCount = document.getElementById("notification-count");
  const notificationDialog = document.getElementById("notification-dialog");
  const notificationList = document.getElementById("notification-list");
  const notificationStatus = document.getElementById("notification-status");
  const markNotificationsRead = document.getElementById("mark-notifications-read");
  const profileButton = document.querySelector('[data-action="profile"]');
  const friendsButton = document.querySelector('[data-action="friends"]');
  const logoutButton = document.querySelector('[data-action="logout"]');
  const profileDialog = document.getElementById("profile-dialog");
  const profileForm = document.getElementById("profile-form");
  const profileNickname = document.getElementById("profile-nickname");
  const profileStatusText = document.getElementById("profile-status-text");
  const profileAvatar = document.getElementById("profile-avatar");
  const profileCurrentPassword = document.getElementById("profile-current-password");
  const profileNewPassword = document.getElementById("profile-new-password");
  const profileConfirmPassword = document.getElementById("profile-confirm-password");
  const profileAvatarPreview = document.getElementById("profile-avatar-preview");
  const profilePreviewName = document.getElementById("profile-preview-name");
  const profileStatus = document.getElementById("profile-status");
  const friendsDialog = document.getElementById("friends-dialog");
  const friendsForm = document.getElementById("friends-form");
  const friendSearch = document.getElementById("friend-search");
  const friendSearchResults = document.getElementById("friend-search-results");
  const friendList = document.getElementById("friend-list");
  const chatHeading = document.getElementById("chat-heading");
  const messageList = document.getElementById("message-list");
  const messageInput = document.getElementById("message-input");
  const messageFileSelect = document.getElementById("message-file-select");
  const friendsStatus = document.getElementById("friends-status");
  const sendMessageButton = document.getElementById("send-message-button");
  const shareDialog = document.getElementById("share-dialog");
  const shareForm = document.getElementById("share-form");
  const shareOutput = document.getElementById("share-output");
  const copyShareLinkButton = document.getElementById("copy-share-link-button");
  const permissionDialog = document.getElementById("permission-dialog");
  const permissionForm = document.getElementById("permission-form");
  const permissionUser = document.getElementById("permission-user");
  const permissionTags = document.getElementById("permission-tags");
  const knownTags = document.getElementById("known-tags");
  const selectionBox = document.getElementById("selection-box");
  let pendingUploads = [];
  let permissions = { users: [], grants: {}, tags: [] };
  let selectedPermissionUser = "";
  let notifications = [];
  let profileAvatarData = "";

  const buttons = {
    download: document.querySelector('[data-action="download-selected"]'),
    share: document.querySelector('[data-action="share-selected"]'),
    copy: document.querySelector('[data-action="copy-selected"]'),
    cut: document.querySelector('[data-action="cut-selected"]'),
    rename: document.querySelector('[data-action="rename-selected"]'),
    delete: document.querySelector('[data-action="delete-selected"]'),
    paste: document.querySelector('[data-action="paste"]')
  };

  function notify(message, tone = "info") {
    summary.textContent = message;
    summary.dataset.tone = tone;
  }

  async function api(path, options = {}) {
    const headers = {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(SAFE_WRITE_METHODS.has((options.method || "GET").toUpperCase()) && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...(options.headers || {})
    };

    const response = await fetch(path, {
      ...options,
      credentials: "same-origin",
      headers
    });

    if (!response.ok) {
      let message = "请求失败";
      try {
        const data = await response.json();
        message = data.error || message;
      } catch {}
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }

    return response.json();
  }

  function setUploadBusy(isBusy) {
    confirmUploadButton.disabled = isBusy || pendingUploads.length === 0 || Boolean(validatePendingUploads());
    fileInput.disabled = isBusy;
    document.getElementById("retention-select").disabled = isBusy;
    document.getElementById("custom-expiry").disabled = isBusy;
    for (const control of uploadFileList.querySelectorAll("textarea, input")) {
      control.disabled = isBusy;
    }
    for (const button of uploadForm.querySelectorAll('[data-action="close-dialog"]')) {
      button.disabled = isBusy;
    }
  }

  function resetUploadProgress() {
    uploadProgressWrap.hidden = true;
    uploadProgress.value = 0;
    uploadProgress.removeAttribute("value");
    uploadProgressText.value = "等待上传";
  }

  function updateUploadProgress(loaded, total) {
    uploadProgressWrap.hidden = false;
    if (total > 0) {
      const percent = Math.min(100, Math.max(0, Math.round((loaded / total) * 100)));
      uploadProgress.value = percent;
      uploadProgressText.value = percent >= 100
        ? "已发送，正在保存到存储..."
        : "正在上传 " + percent + "% (" + formatSize(loaded) + " / " + formatSize(total) + ")";
      return;
    }
    uploadProgress.removeAttribute("value");
    uploadProgressText.value = "正在上传...";
  }

  function uploadFormData(path, form, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", path);
      xhr.responseType = "json";
      xhr.withCredentials = true;
      if (csrfToken) xhr.setRequestHeader("X-CSRF-Token", csrfToken);
      xhr.upload.addEventListener("progress", (event) => {
        if (onProgress) onProgress(event.loaded, event.lengthComputable ? event.total : 0);
        else updateUploadProgress(event.loaded, event.lengthComputable ? event.total : 0);
      });
      xhr.addEventListener("load", () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(xhr.response || {});
          return;
        }
        let data = xhr.response || {};
        if (typeof data !== "object") {
          try {
            data = JSON.parse(xhr.responseText || "{}");
          } catch {
            data = {};
          }
        }
        reject(new Error(data.error || "上传失败"));
      });
      xhr.addEventListener("error", () => reject(new Error("网络错误，上传失败")));
      xhr.addEventListener("abort", () => reject(new Error("上传已取消")));
      xhr.send(form);
    });
  }

  function requestWithProgress(method, path, body, onProgress, options = {}) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, path);
      xhr.responseType = "json";
      xhr.withCredentials = options.withCredentials !== false;
      if (options.csrf !== false && csrfToken) xhr.setRequestHeader("X-CSRF-Token", csrfToken);
      for (const [name, value] of Object.entries(options.headers || {})) {
        xhr.setRequestHeader(name, value);
      }
      xhr.upload.addEventListener("progress", (event) => {
        if (event.lengthComputable && onProgress) onProgress(event.loaded, event.total);
      });
      xhr.addEventListener("load", () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(xhr.response || {});
          return;
        }
        let data = xhr.response || {};
        if (typeof data !== "object") {
          try {
            data = JSON.parse(xhr.responseText || "{}");
          } catch {
            data = {};
          }
        }
        reject(new Error(data.error || "上传失败"));
      });
      xhr.addEventListener("error", () => reject(new Error("网络错误，上传失败")));
      xhr.addEventListener("abort", () => reject(new Error("上传已取消")));
      xhr.send(body);
    });
  }

  async function directUploadFile(item, context) {
    const form = new FormData();
    form.append("files", item.file);
    form.append("description:0", item.description);
    form.append("tags:0", tagsToText(item.tags));
    form.append("expiresAt", getExpiryValue());
    const start = context.doneBytes;
    const data = await uploadFormData("/api/files", form, (loaded) => {
      updateUploadProgress(start + loaded, context.totalBytes);
    });
    context.doneBytes += item.file.size;
    updateUploadProgress(context.doneBytes, context.totalBytes);
    return data.files?.[0] || null;
  }

  async function storageDirectUploadFile(item, context) {
    const file = item.file;
    const create = await api("/api/uploads/direct", {
      method: "POST",
      body: JSON.stringify({
        name: file.name,
        size: file.size,
        contentType: file.type || "application/octet-stream",
        description: item.description,
        tags: item.tags,
        expiresAt: getExpiryValue()
      })
    });
    const start = context.doneBytes;
    await requestWithProgress(create.upload.method || "PUT", create.upload.url, file, (loaded) => {
      updateUploadProgress(start + loaded, context.totalBytes);
    }, {
      withCredentials: false,
      headers: create.upload.headers || {},
      csrf: false
    });
    const completed = await api("/api/uploads/direct/" + encodeURIComponent(create.id) + "/complete", {
      method: "POST",
      body: JSON.stringify({
        name: file.name,
        size: file.size,
        contentType: file.type || "application/octet-stream",
        description: item.description,
        tags: item.tags,
        expiresAt: getExpiryValue()
      })
    }, 201);
    context.doneBytes += file.size;
    updateUploadProgress(context.doneBytes, context.totalBytes);
    return completed.file;
  }

  async function multipartUploadFile(item, context) {
    const file = item.file;
    const create = await api("/api/uploads/multipart", {
      method: "POST",
      body: JSON.stringify({
        name: file.name,
        size: file.size,
        contentType: file.type || "application/octet-stream",
        description: item.description,
        tags: item.tags,
        expiresAt: getExpiryValue()
      })
    });
    const partSize = Math.max(5 * 1024 * 1024, Number(create.partSize || uploadLimits.chunkBytes || 16 * 1024 * 1024));
    const parts = [];
    let uploadedForFile = 0;

    try {
      for (let offset = 0, partNumber = 1; offset < file.size || (file.size === 0 && partNumber === 1); offset += partSize, partNumber += 1) {
        const chunk = file.slice(offset, Math.min(offset + partSize, file.size));
        const part = await requestWithProgress(
          "PUT",
          "/api/uploads/multipart/" +
            encodeURIComponent(create.id) +
            "/" +
            encodeURIComponent(create.uploadId) +
            "/" +
            partNumber,
          chunk,
          (loaded) => {
            updateUploadProgress(context.doneBytes + uploadedForFile + loaded, context.totalBytes);
          }
        );
        parts.push(part);
        uploadedForFile += chunk.size;
        updateUploadProgress(context.doneBytes + uploadedForFile, context.totalBytes);
      }

      const completed = await api(
        "/api/uploads/multipart/" + encodeURIComponent(create.id) + "/" + encodeURIComponent(create.uploadId) + "/complete",
        {
          method: "POST",
          body: JSON.stringify({
            name: file.name,
            size: file.size,
            contentType: file.type || "application/octet-stream",
            description: item.description,
            tags: item.tags,
            expiresAt: getExpiryValue(),
            parts
          })
        },
        201
      );
      context.doneBytes += file.size;
      return completed.file;
    } catch (error) {
      await api("/api/uploads/multipart/" + encodeURIComponent(create.id) + "/" + encodeURIComponent(create.uploadId), {
        method: "DELETE",
        body: JSON.stringify({})
      }).catch(() => {});
      throw error;
    }
  }

  async function logout() {
    await api("/api/auth/logout", {
      method: "POST",
      body: JSON.stringify({})
    });
    location.reload();
  }

  function formatDate(value) {
    if (!value) return "从未";
    return new Intl.DateTimeFormat("zh-CN", {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(value));
  }

  function formatSize(bytes) {
    if (!Number.isFinite(bytes)) return "";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let size = bytes;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    return size.toFixed(size >= 10 || unit === 0 ? 0 : 1) + " " + units[unit];
  }

  function ext(name) {
    const match = name.match(/\.([^.]+)$/);
    return match ? match[1].slice(0, 4).toUpperCase() : "FILE";
  }

  function parseTags(value) {
    const seen = new Set();
    const tags = [];
    for (const raw of String(value || "").split(/[,，\n]+/)) {
      const tag = raw.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 32);
      const key = tag.toLocaleLowerCase();
      if (!tag || seen.has(key)) continue;
      seen.add(key);
      tags.push(tag);
      if (tags.length >= 20) break;
    }
    return tags;
  }

  function tagsToText(tags) {
    return (tags || []).join(", ");
  }

  function setTagFilter(tag) {
    state.tag = tag || "";
    clearFilterButton.hidden = !state.tag && !state.query;
    loadFiles().catch((error) => notify(error.message, "error"));
  }

  function selectedFiles() {
    return state.files.filter((file) => state.selected.has(file.id));
  }

  function updateButtons() {
    const count = state.selected.size;
    for (const key of ["download", "share", "copy", "cut", "delete"]) {
      buttons[key].disabled = count === 0;
    }
    buttons.rename.disabled = count !== 1;
    buttons.paste.disabled = !state.clipboard;
    summary.textContent = count
      ? "已选择 " + count + " 个文件"
      : state.tag
        ? "已筛选标签：" + state.tag
        : "未选择文件";
    storageCount.textContent = state.files.length + " 个文件";
    clearFilterButton.hidden = !state.tag && !state.query;
  }

  function renderTags(container, tags) {
    container.innerHTML = "";
    if (!tags?.length) {
      const emptyTag = document.createElement("span");
      emptyTag.className = "tag-empty";
      emptyTag.textContent = "无标签";
      container.append(emptyTag);
      return;
    }

    for (const tag of tags) {
      const chip = document.createElement("span");
      chip.className = "tag-chip";
      chip.role = "button";
      chip.tabIndex = 0;
      chip.textContent = tag;
      chip.addEventListener("click", (event) => {
        event.stopPropagation();
        setTagFilter(tag);
      });
      chip.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        event.stopPropagation();
        setTagFilter(tag);
      });
      container.append(chip);
    }
  }

  function render() {
    list.innerHTML = "";
    for (const file of state.files) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "file-row";
      row.dataset.id = file.id;
      row.classList.toggle("selected", state.selected.has(file.id));
      row.classList.toggle(
        "cut",
        state.clipboard?.mode === "cut" && state.clipboard.ids.includes(file.id)
      );

      row.innerHTML =
        '<span class="file-name">' +
          '<span class="file-icon"></span>' +
          '<span>' +
            '<strong class="file-title"></strong>' +
            '<small class="file-size">' + formatSize(file.size) + '</small>' +
          '</span>' +
        '</span>' +
        '<span class="file-description"></span>' +
        '<span class="file-tags"></span>' +
        '<span>' + formatDate(file.uploadedAt) + '</span>' +
        '<span>' + formatDate(file.lastDownloadedAt) + '</span>' +
        '<span>' + file.downloadCount + '</span>';
      row.querySelector(".file-icon").textContent = ext(file.name);
      row.querySelector(".file-title").textContent = file.name;
      row.querySelector(".file-description").textContent = file.description || "无描述";
      renderTags(row.querySelector(".file-tags"), file.tags || []);

      row.addEventListener("click", (event) => {
        if (event.shiftKey || event.metaKey || event.ctrlKey) {
          toggle(file.id);
        } else {
          state.selected.clear();
          state.selected.add(file.id);
        }
        hideMenu();
        render();
      });

      row.addEventListener("dblclick", () => downloadIds([file.id]));
      row.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        if (!state.selected.has(file.id)) {
          state.selected.clear();
          state.selected.add(file.id);
          render();
        }
        state.contextId = file.id;
        showMenu(event.clientX, event.clientY);
      });

      list.append(row);
    }

    empty.hidden = state.files.length !== 0;
    updateButtons();
  }

  function toggle(id) {
    if (state.selected.has(id)) state.selected.delete(id);
    else state.selected.add(id);
  }

  function hideMenu() {
    menu.hidden = true;
  }

  function showMenu(x, y) {
    menu.hidden = false;
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - rect.width - 10) + "px";
    menu.style.top = Math.min(y, window.innerHeight - rect.height - 10) + "px";
  }

  async function loadFiles() {
    notify("正在读取文件...");
    const url = new URL("/api/files", location.origin);
    if (state.query) url.searchParams.set("q", state.query);
    if (state.tag) url.searchParams.set("tag", state.tag);
    const data = await api(url.pathname + url.search);
    state.files = data.files || [];
    state.selected.clear();
    render();
  }

  async function loadFilesSilently() {
    const url = new URL("/api/files", location.origin);
    if (state.query) url.searchParams.set("q", state.query);
    if (state.tag) url.searchParams.set("tag", state.tag);
    const data = await api(url.pathname + url.search);
    state.files = data.files || [];
  }

  function getExpiryValue() {
    const select = document.getElementById("retention-select");
    const custom = document.getElementById("custom-expiry");
    if (!select.value) return "";
    if (select.value === "custom") return custom.value ? new Date(custom.value).toISOString() : "";
    const date = new Date();
    date.setDate(date.getDate() + Number(select.value));
    return date.toISOString();
  }

  function renderPendingUploads() {
    uploadFileList.innerHTML = "";
    for (const item of pendingUploads) {
      const row = document.createElement("div");
      row.className = "upload-file-row";
      row.innerHTML =
        '<span class="upload-file-meta">' +
          '<strong></strong>' +
          '<small>' + formatSize(item.file.size) + '</small>' +
        '</span>' +
        '<textarea maxlength="500" rows="1" placeholder="该文件的描述"></textarea>' +
        '<input placeholder="该文件的标签" autocomplete="off" />';
      row.querySelector("strong").textContent = item.file.name;
      const textarea = row.querySelector("textarea");
      textarea.value = item.description;
      textarea.addEventListener("input", () => {
        item.description = textarea.value;
      });
      const tagInput = row.querySelector("input");
      tagInput.value = tagsToText(item.tags);
      tagInput.addEventListener("input", () => {
        item.tags = parseTags(tagInput.value);
      });
      uploadFileList.append(row);
    }
    confirmUploadButton.disabled = pendingUploads.length === 0 || Boolean(validatePendingUploads());
  }

  function renderNotifications() {
    notificationList.innerHTML = "";
    if (!notifications.length) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "暂无通知";
      notificationList.append(empty);
    }

    let unread = 0;
    for (const notification of notifications) {
      if (!notification.readAt) unread += 1;
      const item = document.createElement("article");
      item.className = "notification-item" + (notification.readAt ? "" : " unread");
      item.innerHTML =
        '<header>' +
          '<strong></strong>' +
          '<small></small>' +
        '</header>' +
        '<p></p>' +
        '<small class="notification-from"></small>';
      item.querySelector("strong").textContent = notification.title || "通知";
      item.querySelector("small").textContent = formatDate(notification.createdAt);
      item.querySelector("p").textContent = notification.message || "";
      item.querySelector(".notification-from").textContent = "来自 " + (notification.from || "admin");
      notificationList.append(item);
    }

    notificationCount.textContent = unread ? unread + " 条未读" : "";
    notificationStatus.textContent = notifications.length ? notifications.length + " 条通知" : "暂无通知";
    markNotificationsRead.disabled = unread === 0;
  }

  async function loadNotifications() {
    const data = await api("/api/notifications");
    notifications = data.notifications || [];
    renderNotifications();
  }

  async function openNotificationDialog() {
    await loadNotifications();
    notificationDialog.showModal();
  }

  async function markAllNotificationsRead() {
    await api("/api/notifications/read", {
      method: "PATCH",
      body: JSON.stringify({})
    });
    await loadNotifications();
  }

  function initials(user) {
    const label = user?.nickname || user?.name || "?";
    return label.slice(0, 2).toUpperCase();
  }

  function renderAvatar(container, user) {
    container.innerHTML = "";
    if (user?.avatar) {
      const image = document.createElement("img");
      image.src = user.avatar;
      image.alt = "";
      container.append(image);
      return;
    }
    container.textContent = initials(user);
  }

  async function loadMe() {
    const data = await api("/api/me");
    state.me = data.user || null;
    return state.me;
  }

  function renderProfileForm() {
    const me = state.me || { name: appRoot?.dataset.user || "" };
    profileNickname.value = me.nickname || "";
    profileStatusText.value = me.status || "";
    profileCurrentPassword.value = "";
    profileNewPassword.value = "";
    profileConfirmPassword.value = "";
    profileAvatarData = me.avatar || "";
    profilePreviewName.textContent = (me.nickname ? me.nickname + " · " : "") + me.name;
    renderAvatar(profileAvatarPreview, me);
  }

  async function openProfileDialog() {
    await loadMe();
    renderProfileForm();
    profileStatus.value = "";
    profileDialog.showModal();
  }

  async function saveProfile(event) {
    event.preventDefault();
    if (profileNewPassword.value || profileConfirmPassword.value) {
      if (profileNewPassword.value !== profileConfirmPassword.value) {
        profileStatus.value = "两次输入的新密码不一致";
        return;
      }
      if (profileNewPassword.value.length < 6) {
        profileStatus.value = "新密码至少需要 6 位";
        return;
      }
      if (!profileCurrentPassword.value) {
        profileStatus.value = "请输入当前密码";
        return;
      }
    }
    profileStatus.value = "正在保存...";
    const data = await api("/api/me/profile", {
      method: "PATCH",
      body: JSON.stringify({
        nickname: profileNickname.value,
        status: profileStatusText.value,
        avatar: profileAvatarData,
        currentPassword: profileCurrentPassword.value,
        newPassword: profileNewPassword.value
      })
    });
    await loadMe();
    renderProfileForm();
    profileStatus.value = data.passwordChanged ? "账号设置已保存，请使用新密码登录" : "账号设置已保存";
  }

  function readAvatarFile(file) {
    return new Promise((resolve, reject) => {
      if (!file) {
        resolve("");
        return;
      }
      if (file.size > 36000) {
        reject(new Error("头像不能超过 36KB"));
        return;
      }
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("头像读取失败"));
      reader.readAsDataURL(file);
    });
  }

  function userLine(user) {
    return (user.nickname ? user.nickname + " · " : "") + user.name;
  }

  function renderCompactUser(user, actionText, onAction) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "compact-user" + (state.activeFriend === user.name ? " active" : "");
    row.innerHTML =
      '<span class="avatar"></span>' +
      '<span>' +
        '<strong></strong>' +
        '<small></small>' +
      '</span>' +
      '<span class="tag-chip"></span>';
    renderAvatar(row.querySelector(".avatar"), user);
    row.querySelector("strong").textContent = user.nickname || user.name;
    row.querySelector("small").textContent = user.status || (user.nickname ? user.name : (user.tags || []).join(", ") || "用户");
    row.querySelector(".tag-chip").textContent = actionText;
    row.addEventListener("click", () => onAction(user));
    return row;
  }

  function renderFriendLists() {
    friendList.innerHTML = "";
    friendSearchResults.innerHTML = "";

    if (!state.friendResults.length && friendSearch.value.trim()) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "没有匹配用户";
      friendSearchResults.append(empty);
    }
    for (const user of state.friendResults) {
      friendSearchResults.append(renderCompactUser(user, user.isFriend ? "已添加" : "添加", async (target) => {
        if (!target.isFriend) await addFriendNow(target.name);
        await selectFriend(target.name);
      }));
    }

    if (!state.friends.length) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "还没有好友";
      friendList.append(empty);
    }
    for (const user of state.friends) {
      friendList.append(renderCompactUser(user, "聊天", (target) => selectFriend(target.name)));
    }
  }

  function renderMessageFiles() {
    messageFileSelect.innerHTML = "";
    for (const file of state.files) {
      const option = document.createElement("option");
      option.value = file.id;
      option.textContent = file.name;
      messageFileSelect.append(option);
    }
  }

  async function loadFriends() {
    const data = await api("/api/friends");
    state.friends = data.friends || [];
    if (state.activeFriend && !state.friends.some((friend) => friend.name === state.activeFriend)) {
      state.activeFriend = "";
    }
    renderFriendLists();
  }

  async function searchUsers() {
    const query = friendSearch.value.trim();
    if (!query) {
      state.friendResults = [];
      renderFriendLists();
      return;
    }
    const data = await api("/api/users/search?q=" + encodeURIComponent(query));
    state.friendResults = data.users || [];
    renderFriendLists();
  }

  async function addFriendNow(user) {
    friendsStatus.textContent = "正在添加好友...";
    await api("/api/friends/" + encodeURIComponent(user), { method: "POST", body: JSON.stringify({}) });
    await loadFriends();
    state.friendResults = state.friendResults.map((item) => item.name === user ? { ...item, isFriend: true } : item);
    renderFriendLists();
    friendsStatus.textContent = "好友已添加";
  }

  function renderMessages(messages) {
    messageList.innerHTML = "";
    if (!messages.length) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "还没有私信";
      messageList.append(empty);
      return;
    }

    for (const message of messages) {
      const item = document.createElement("article");
      item.className = "message-item" + (message.from === state.me?.name ? " own" : "");
      item.innerHTML = '<small></small><p></p><div class="message-files"></div>';
      item.querySelector("small").textContent = formatDate(message.createdAt);
      item.querySelector("p").textContent = message.message || "";
      const files = item.querySelector(".message-files");
      for (const file of message.files || []) {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "tag-chip";
        chip.textContent = file.name;
        chip.addEventListener("click", () => downloadIds([file.id]).catch((error) => notify(error.message, "error")));
        files.append(chip);
      }
      messageList.append(item);
    }
    messageList.scrollTop = messageList.scrollHeight;
  }

  async function selectFriend(user) {
    state.activeFriend = user;
    const friend = state.friends.find((item) => item.name === user) || state.friendResults.find((item) => item.name === user);
    chatHeading.textContent = friend ? userLine(friend) : user;
    sendMessageButton.disabled = false;
    renderFriendLists();
    const data = await api("/api/messages/" + encodeURIComponent(user));
    renderMessages(data.messages || []);
    friendsStatus.textContent = "正在和 " + (friend?.nickname || user) + " 对话";
  }

  async function openFriendsDialog() {
    await Promise.all([loadMe(), loadFriends(), loadFilesSilently()]);
    renderMessageFiles();
    friendsDialog.showModal();
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (!state.activeFriend) return;
    const fileIds = Array.from(messageFileSelect.selectedOptions).map((option) => option.value);
    await api("/api/messages/" + encodeURIComponent(state.activeFriend), {
      method: "POST",
      body: JSON.stringify({
        message: messageInput.value,
        fileIds
      })
    });
    messageInput.value = "";
    for (const option of messageFileSelect.options) option.selected = false;
    await selectFriend(state.activeFriend);
    await loadNotifications();
  }

  function resetUploadDialog() {
    pendingUploads = [];
    fileInput.value = "";
    document.getElementById("retention-select").value = "";
    document.getElementById("custom-expiry").value = "";
    document.getElementById("custom-expiry").hidden = true;
    resetUploadProgress();
    setUploadBusy(false);
    renderPendingUploads();
  }

  function openUploadDialog() {
    resetUploadDialog();
    uploadDialog.showModal();
  }

  function updatePendingFiles() {
    pendingUploads = Array.from(fileInput.files || []).map((file) => ({
      file,
      description: "",
      tags: []
    }));
    renderPendingUploads();
    const validationError = validatePendingUploads();
    if (validationError) {
      uploadProgressWrap.hidden = false;
      uploadProgress.removeAttribute("value");
      uploadProgressText.value = validationError;
      notify(validationError, "error");
    } else {
      resetUploadProgress();
    }
  }

  function validatePendingUploads() {
    if (!pendingUploads.length) return "";
    const oversized = pendingUploads.find((item) => uploadLimits.maxFileBytes && item.file.size > uploadLimits.maxFileBytes);
    if (oversized) {
      return "文件 " + oversized.file.name + " 超过单文件上限 " + formatSize(uploadLimits.maxFileBytes);
    }
    return "";
  }

  async function uploadSelected(event) {
    event.preventDefault();
    const uploads = pendingUploads.slice();
    if (!uploads.length) return;
    const validationError = validatePendingUploads();
    if (validationError) {
      uploadProgressWrap.hidden = false;
      uploadProgress.removeAttribute("value");
      uploadProgressText.value = validationError;
      notify(validationError, "error");
      return;
    }

    notify("正在上传 " + uploads.length + " 个文件...");
    const uploadContext = {
      doneBytes: 0,
      totalBytes: uploads.reduce((sum, item) => sum + item.file.size, 0)
    };
    updateUploadProgress(0, uploadContext.totalBytes);
    setUploadBusy(true);
    try {
      for (const item of uploads) {
        uploadProgressText.value = "正在上传 " + item.file.name;
        if (item.file.size < Math.max(5 * 1024 * 1024, uploadLimits.chunkBytes || 16 * 1024 * 1024)) {
          await directUploadFile(item, uploadContext);
        } else {
          try {
            await storageDirectUploadFile(item, uploadContext);
          } catch (error) {
            if (error.status !== 501 && !/不支持直传/.test(error.message || "")) throw error;
            await multipartUploadFile(item, uploadContext);
          }
        }
      }
      uploadProgress.value = 100;
      uploadProgressText.value = "上传完成，正在刷新...";
      uploadDialog.close();
      resetUploadDialog();
      await loadFiles();
      notify("上传完成");
    } catch (error) {
      uploadProgressWrap.hidden = false;
      uploadProgress.removeAttribute("value");
      uploadProgressText.value = error.message || "上传失败";
      notify(error.message || "上传失败", "error");
      setUploadBusy(false);
    }
  }

  function triggerBlobDownload(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }

  async function downloadIds(ids) {
    if (!ids.length) return;
    if (ids.length === 1) {
      window.location.href = "/api/files/" + encodeURIComponent(ids[0]) + "/download";
      setTimeout(loadFiles, 1200);
      return;
    }

    notify("正在打包 " + ids.length + " 个文件...");
    const response = await fetch("/api/files/download", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({ ids })
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || "下载失败");
    }
    triggerBlobDownload(await response.blob(), "Cirrus-" + new Date().toISOString().slice(0, 10) + ".zip");
    setTimeout(loadFiles, 1200);
  }

  async function renameSelected() {
    const file = selectedFiles()[0];
    if (!file || state.selected.size !== 1) return;
    const name = prompt("输入新的文件名", file.name);
    if (!name || name === file.name) return;
    await api("/api/files/" + encodeURIComponent(file.id), {
      method: "PATCH",
      body: JSON.stringify({ name })
    });
    await loadFiles();
  }

  async function editDescriptionSelected() {
    const file = selectedFiles()[0];
    if (!file || state.selected.size !== 1) return;
    const description = prompt("输入文件描述", file.description || "");
    if (description === null || description === (file.description || "")) return;
    await api("/api/files/" + encodeURIComponent(file.id) + "/description", {
      method: "PATCH",
      body: JSON.stringify({ description })
    });
    await loadFiles();
  }

  async function editTagsSelected() {
    const file = selectedFiles()[0];
    if (!file || state.selected.size !== 1) return;
    const tags = prompt("输入文件标签，多个标签用逗号分隔", tagsToText(file.tags));
    if (tags === null || tags === tagsToText(file.tags)) return;
    await api("/api/files/" + encodeURIComponent(file.id) + "/tags", {
      method: "PATCH",
      body: JSON.stringify({ tags: parseTags(tags) })
    });
    await loadFiles();
  }

  async function deleteSelected() {
    const ids = Array.from(state.selected);
    if (!ids.length) return;
    if (!confirm("删除 " + ids.length + " 个文件？")) return;
    await api("/api/files", {
      method: "DELETE",
      body: JSON.stringify({ ids })
    });
    await loadFiles();
  }

  async function copySelectedNow() {
    const ids = Array.from(state.selected);
    if (!ids.length) return;
    await api("/api/files/copy", {
      method: "POST",
      body: JSON.stringify({ ids })
    });
    await loadFiles();
    notify("已复制为副本");
  }

  function setClipboard(mode) {
    const ids = Array.from(state.selected);
    if (!ids.length) return;
    state.clipboard = { mode, ids };
    render();
    notify(mode === "cut" ? "已剪切，当前网盘没有文件夹时粘贴会保留原位置" : "已复制，可用左侧粘贴生成副本");
  }

  async function pasteClipboard() {
    if (!state.clipboard) return;
    if (state.clipboard.mode === "copy") {
      await api("/api/files/copy", {
        method: "POST",
        body: JSON.stringify({ ids: state.clipboard.ids })
      });
      state.clipboard = null;
      await loadFiles();
      notify("已粘贴副本");
      return;
    }
    state.clipboard = null;
    render();
    notify("已清除剪切状态");
  }

  function openShareDialog() {
    if (!state.selected.size) return;
    document.getElementById("share-code").value = "";
    document.getElementById("share-password").value = "";
    document.getElementById("share-expiry").value = "";
    shareOutput.value = "";
    copyShareLinkButton.disabled = true;
    shareDialog.showModal();
  }

  async function copyShareLink(message = "复制成功") {
    const url = shareOutput.value.trim();
    if (!url) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
      } else {
        shareOutput.focus();
        shareOutput.select();
        if (!document.execCommand("copy")) throw new Error("复制失败");
      }
    } catch {
      shareOutput.focus();
      shareOutput.select();
      if (!document.execCommand("copy")) throw new Error("复制失败");
    }
    notify(message);
  }

  async function createShareFromDialog(event) {
    event.preventDefault();
    const code = document.getElementById("share-code").value;
    const password = document.getElementById("share-password").value;
    const expiry = document.getElementById("share-expiry").value;
    const data = await api("/api/shares", {
      method: "POST",
      body: JSON.stringify({
        fileIds: Array.from(state.selected),
        code,
        password,
        expiresAt: expiry ? new Date(expiry).toISOString() : ""
      })
    });
    shareOutput.value = data.share.url;
    copyShareLinkButton.disabled = false;
    try {
      await copyShareLink("分享链接已生成，复制成功");
    } catch {
      notify("分享链接已生成");
    }
  }

  function renderPermissionForm() {
    if (!permissionUser || !permissionTags || !knownTags) return;

    const currentUser = selectedPermissionUser || permissionUser.value;
    permissionUser.innerHTML = "";
    for (const user of permissions.users) {
      const option = document.createElement("option");
      option.value = user;
      option.textContent = user;
      permissionUser.append(option);
    }

    const selectedUser = permissions.users.includes(currentUser) ? currentUser : permissions.users[0] || "";
    selectedPermissionUser = selectedUser;
    permissionUser.value = selectedUser;
    permissionTags.value = tagsToText(permissions.grants[selectedUser] || []);

    knownTags.innerHTML = "";
    if (!permissions.tags.length) {
      const emptyTag = document.createElement("span");
      emptyTag.className = "tag-empty";
      emptyTag.textContent = "暂无可选标签";
      knownTags.append(emptyTag);
      return;
    }

    for (const tag of permissions.tags) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "tag-chip";
      chip.textContent = tag;
      chip.addEventListener("click", () => {
        const tags = parseTags(permissionTags.value);
        if (!tags.some((item) => item.toLocaleLowerCase() === tag.toLocaleLowerCase())) {
          tags.push(tag);
        }
        permissionTags.value = tagsToText(tags);
      });
      knownTags.append(chip);
    }
  }

  async function openPermissionDialog() {
    if (!isAdmin || !permissionDialog) return;
    const data = await api("/api/admin/permissions");
    permissions = {
      users: data.users || [],
      grants: data.grants || {},
      tags: data.tags || []
    };
    selectedPermissionUser = permissions.users.includes(selectedPermissionUser)
      ? selectedPermissionUser
      : permissions.users[0] || "";
    renderPermissionForm();
    permissionDialog.showModal();
  }

  async function savePermissions(event) {
    event.preventDefault();
    if (!permissionUser.value) {
      notify("没有普通用户可配置", "error");
      return;
    }
    const data = await api("/api/admin/permissions/" + encodeURIComponent(permissionUser.value), {
      method: "PATCH",
      body: JSON.stringify({ tags: parseTags(permissionTags.value) })
    });
    permissions.grants[data.user] = data.tags || [];
    permissionDialog.close();
    notify("权限已保存");
  }

  function updateSelectionBox(start, current) {
    const left = Math.min(start.x, current.x);
    const top = Math.min(start.y, current.y);
    const width = Math.abs(start.x - current.x);
    const height = Math.abs(start.y - current.y);
    const surfaceRect = surface.getBoundingClientRect();
    Object.assign(selectionBox.style, {
      left: (left - surfaceRect.left) + "px",
      top: (top - surfaceRect.top) + "px",
      width: width + "px",
      height: height + "px"
    });

    const box = { left, top, right: left + width, bottom: top + height };
    for (const row of list.querySelectorAll(".file-row")) {
      const rect = row.getBoundingClientRect();
      const hit = rect.left < box.right && rect.right > box.left && rect.top < box.bottom && rect.bottom > box.top;
      const id = row.dataset.id;
      if (hit) state.selected.add(id);
      else if (!state.dragging.additive) state.selected.delete(id);
    }
    render();
    selectionBox.hidden = false;
  }

  surface.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest(".file-row, button, input, select, a")) return;
    hideMenu();
    state.dragging = {
      start: { x: event.clientX, y: event.clientY },
      additive: event.ctrlKey || event.metaKey || event.shiftKey
    };
    if (!state.dragging.additive) state.selected.clear();
    surface.setPointerCapture(event.pointerId);
  });

  surface.addEventListener("pointermove", (event) => {
    if (!state.dragging) return;
    updateSelectionBox(state.dragging.start, { x: event.clientX, y: event.clientY });
  });

  surface.addEventListener("pointerup", (event) => {
    if (!state.dragging) return;
    state.dragging = null;
    selectionBox.hidden = true;
    surface.releasePointerCapture(event.pointerId);
    render();
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".context-menu")) hideMenu();
  });

  let searchTimer = 0;
  searchInput.addEventListener("input", () => {
    state.query = searchInput.value.trim();
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => {
      loadFiles().catch((error) => notify(error.message, "error"));
    }, 180);
  });
  clearFilterButton.addEventListener("click", () => {
    state.query = "";
    state.tag = "";
    searchInput.value = "";
    loadFiles().catch((error) => notify(error.message, "error"));
  });
  document.getElementById("retention-select").addEventListener("change", (event) => {
    document.getElementById("custom-expiry").hidden = event.target.value !== "custom";
  });
  document.querySelector('[data-action="open-upload"]').addEventListener("click", openUploadDialog);
  notificationButton.addEventListener("click", () => openNotificationDialog().catch((error) => notify(error.message, "error")));
  markNotificationsRead.addEventListener("click", () => markAllNotificationsRead().catch((error) => {
    notificationStatus.textContent = error.message;
  }));
  profileButton.addEventListener("click", () => openProfileDialog().catch((error) => notify(error.message, "error")));
  profileForm.addEventListener("submit", (event) => saveProfile(event).catch((error) => {
    profileStatus.value = error.message;
  }));
  profileAvatar.addEventListener("change", () => readAvatarFile(profileAvatar.files?.[0]).then((avatar) => {
    profileAvatarData = avatar;
    renderAvatar(profileAvatarPreview, { name: state.me?.name || "", nickname: profileNickname.value, avatar });
  }).catch((error) => {
    profileStatus.value = error.message;
    profileAvatar.value = "";
  }));
  friendsButton.addEventListener("click", () => openFriendsDialog().catch((error) => notify(error.message, "error")));
  logoutButton.addEventListener("click", () => logout().catch((error) => notify(error.message, "error")));
  let friendSearchTimer = 0;
  friendSearch.addEventListener("input", () => {
    window.clearTimeout(friendSearchTimer);
    friendSearchTimer = window.setTimeout(() => searchUsers().catch((error) => {
      friendsStatus.textContent = error.message;
    }), 180);
  });
  friendsForm.addEventListener("submit", (event) => sendMessage(event).catch((error) => {
    friendsStatus.textContent = error.message;
  }));
  fileInput.addEventListener("change", updatePendingFiles);
  uploadForm.addEventListener("submit", (event) => uploadSelected(event).catch((error) => notify(error.message, "error")));
  document.querySelector('[data-action="refresh"]').addEventListener("click", () => loadFiles().catch((error) => notify(error.message, "error")));
  document.querySelector('[data-action="manage-permissions"]')?.addEventListener("click", () => openPermissionDialog().catch((error) => notify(error.message, "error")));
  permissionUser?.addEventListener("change", () => {
    selectedPermissionUser = permissionUser.value;
    renderPermissionForm();
  });
  permissionForm?.addEventListener("submit", (event) => savePermissions(event).catch((error) => notify(error.message, "error")));
  buttons.download.addEventListener("click", () => downloadIds(Array.from(state.selected)).catch((error) => notify(error.message, "error")));
  buttons.share.addEventListener("click", openShareDialog);
  buttons.copy.addEventListener("click", () => setClipboard("copy"));
  buttons.cut.addEventListener("click", () => setClipboard("cut"));
  buttons.rename.addEventListener("click", () => renameSelected().catch((error) => notify(error.message, "error")));
  buttons.delete.addEventListener("click", () => deleteSelected().catch((error) => notify(error.message, "error")));
  buttons.paste.addEventListener("click", () => pasteClipboard().catch((error) => notify(error.message, "error")));
  copyShareLinkButton.addEventListener("click", () => copyShareLink().catch((error) => notify(error.message, "error")));
  document.querySelectorAll('[data-action="close-dialog"]').forEach((button) => {
    button.addEventListener("click", () => button.closest("dialog")?.close());
  });
  shareForm.addEventListener("submit", (event) => createShareFromDialog(event).catch((error) => notify(error.message, "error")));

  menu.addEventListener("click", (event) => {
    const action = event.target.closest("button")?.dataset.menuAction;
    if (!action) return;
    hideMenu();
    if (action === "rename") renameSelected().catch((error) => notify(error.message, "error"));
    if (action === "description") editDescriptionSelected().catch((error) => notify(error.message, "error"));
    if (action === "tags") editTagsSelected().catch((error) => notify(error.message, "error"));
    if (action === "download") downloadIds(Array.from(state.selected)).catch((error) => notify(error.message, "error"));
    if (action === "select") render();
    if (action === "copy") setClipboard("copy");
    if (action === "cut") setClipboard("cut");
    if (action === "share") openShareDialog();
  });

  loadFiles().catch((error) => notify(error.message, "error"));
  loadMe().catch(() => {});
  loadNotifications().catch(() => {});
})();
`;

const authClientScript = String.raw`
(() => {
  const dialog = document.getElementById("auth-dialog");
  const form = document.getElementById("auth-form");
  const title = document.getElementById("auth-title");
  const username = document.getElementById("auth-username");
  const password = document.getElementById("auth-password");
  const confirmRow = document.getElementById("auth-confirm-row");
  const confirmPassword = document.getElementById("auth-confirm-password");
  const status = document.getElementById("auth-status");
  const modeButton = document.getElementById("auth-mode-button");
  const submitButton = document.getElementById("auth-submit-button");
  let mode = "login";

  function setMode(nextMode) {
    mode = nextMode;
    const isRegister = mode === "register";
    title.textContent = isRegister ? "注册" : "登录";
    confirmRow.hidden = !isRegister;
    modeButton.textContent = isRegister ? "返回登录" : "注册账号";
    submitButton.textContent = isRegister ? "注册并登录" : "登录";
    password.autocomplete = isRegister ? "new-password" : "current-password";
    status.value = "";
  }

  async function submit(event) {
    event.preventDefault();
    const body = {
      username: username.value.trim(),
      password: password.value
    };
    if (mode === "register") {
      body.confirmPassword = confirmPassword.value;
      if (body.password !== body.confirmPassword) {
        status.value = "两次输入的密码不一致";
        return;
      }
    }

    status.value = mode === "register" ? "正在注册..." : "正在登录...";
    const response = await fetch(mode === "register" ? "/api/auth/register" : "/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      status.value = data.error || "请求失败";
      return;
    }
    location.reload();
  }

  modeButton.addEventListener("click", () => setMode(mode === "login" ? "register" : "login"));
  form.addEventListener("submit", (event) => submit(event).catch((error) => {
    status.value = error.message;
  }));
  setMode("login");
  dialog.showModal();
})();
`;

const adminClientScript = String.raw`
(() => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const state = {
    users: [],
    files: [],
    selected: new Set(),
    tags: []
  };

  const userList = document.getElementById("admin-user-list");
  const count = document.getElementById("admin-count");
  const status = document.getElementById("admin-status");
  const form = document.getElementById("admin-batch-form");
  const roleInput = document.getElementById("admin-role");
  const tagInput = document.getElementById("admin-user-tags");
  const tagModeInput = document.getElementById("admin-tag-mode");
  const clearUserTagsInput = document.getElementById("admin-clear-user-tags");
  const visibleTagInput = document.getElementById("admin-visible-tags");
  const visibleTagModeInput = document.getElementById("admin-visible-tag-mode");
  const clearVisibleTagsInput = document.getElementById("admin-clear-visible-tags");
  const fileInput = document.getElementById("admin-visible-files");
  const fileModeInput = document.getElementById("admin-file-mode");
  const clearVisibleFilesInput = document.getElementById("admin-clear-visible-files");
  const noticeTitle = document.getElementById("admin-notice-title");
  const noticeMessage = document.getElementById("admin-notice-message");
  const userKnownTags = document.getElementById("admin-user-known-tags");
  const visibleKnownTags = document.getElementById("admin-visible-known-tags");

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const response = await fetch(path, {
      ...options,
      credentials: "same-origin",
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(method === "GET" ? {} : { "X-CSRF-Token": csrfToken }),
        ...(options.headers || {})
      }
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "请求失败");
    return data;
  }

  function parseTags(value) {
    const seen = new Set();
    const tags = [];
    for (const raw of String(value || "").split(/[,，\n]+/)) {
      const tag = raw.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 32);
      const key = tag.toLocaleLowerCase();
      if (!tag || seen.has(key)) continue;
      seen.add(key);
      tags.push(tag);
      if (tags.length >= 20) break;
    }
    return tags;
  }

  function tagsToText(tags) {
    return (tags || []).join(", ");
  }

  function renderTags(container, tags) {
    container.innerHTML = "";
    if (!tags?.length) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "无标签";
      container.append(empty);
      return;
    }
    for (const tag of tags) {
      const chip = document.createElement("span");
      chip.className = "tag-chip";
      chip.textContent = tag;
      container.append(chip);
    }
  }

  function renderFiles() {
    fileInput.innerHTML = "";
    for (const file of state.files) {
      const option = document.createElement("option");
      option.value = file.id;
      option.textContent = file.name + (file.owner ? " · " + file.owner : "");
      fileInput.append(option);
    }
  }

  function renderKnownTags() {
    userKnownTags.innerHTML = "";
    visibleKnownTags.innerHTML = "";
    if (!state.tags.length) {
      const empty = document.createElement("span");
      empty.className = "tag-empty";
      empty.textContent = "暂无文件标签";
      userKnownTags.append(empty.cloneNode(true));
      visibleKnownTags.append(empty);
      return;
    }

    for (const tag of state.tags) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "tag-chip";
      chip.textContent = tag;
      chip.addEventListener("click", () => {
        const next = parseTags(tagInput.value);
        if (!next.some((item) => item.toLocaleLowerCase() === tag.toLocaleLowerCase())) {
          next.push(tag);
        }
        tagInput.value = tagsToText(next);
      });
      userKnownTags.append(chip);

      const visibleChip = document.createElement("button");
      visibleChip.type = "button";
      visibleChip.className = "tag-chip";
      visibleChip.textContent = tag;
      visibleChip.addEventListener("click", () => {
        const next = parseTags(visibleTagInput.value);
        if (!next.some((item) => item.toLocaleLowerCase() === tag.toLocaleLowerCase())) {
          next.push(tag);
        }
        visibleTagInput.value = tagsToText(next);
      });
      visibleKnownTags.append(visibleChip);
    }
  }

  function updateStatus() {
    const selectedCount = state.selected.size;
    status.textContent = selectedCount ? "已选择 " + selectedCount + " 个用户" : "请选择用户";
    count.textContent = state.users.length + " 个用户";
  }

  function renderUsers() {
    userList.innerHTML = "";
    for (const user of state.users) {
      const row = document.createElement("label");
      row.className = "user-row";
      row.innerHTML =
        '<span class="user-cell">' +
          '<strong></strong>' +
          '<small></small>' +
        '</span>' +
        '<span class="user-cell role-cell"></span>' +
        '<span class="user-cell user-tags"></span>' +
        '<span class="user-cell visible-tags"></span>' +
        '<span class="user-cell file-cell"></span>' +
        '<span class="user-cell notice-cell"></span>';

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = state.selected.has(user.name);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) state.selected.add(user.name);
        else state.selected.delete(user.name);
        updateStatus();
      });
      row.querySelector("strong").before(checkbox);
      row.querySelector("strong").textContent = user.name;
      row.querySelector("small").textContent = user.ownedCount + " 个自有文件";
      row.querySelector(".role-cell").textContent = user.role === "admin" ? "管理员" : "普通用户";
      renderTags(row.querySelector(".user-tags"), user.tags || []);
      renderTags(row.querySelector(".visible-tags"), user.visibleTags || []);
      row.querySelector(".file-cell").textContent = (user.visibleFileIds || []).length + " 个指定文件";
      row.querySelector(".notice-cell").textContent = (user.unreadNotificationCount || 0) + " 条未读";
      userList.append(row);
    }
    updateStatus();
  }

  async function load() {
    status.textContent = "正在读取管理数据...";
    const data = await api("/api/admin/overview");
    state.users = data.users || [];
    state.files = data.files || [];
    state.tags = data.tags || [];
    state.selected = new Set(Array.from(state.selected).filter((user) => state.users.some((item) => item.name === user)));
    renderFiles();
    renderKnownTags();
    renderUsers();
    status.textContent = "管理数据已更新";
  }

  async function applyBatch(event) {
    event.preventDefault();
    const users = Array.from(state.selected);
    if (!users.length) {
      status.textContent = "请先选择用户";
      return;
    }

    const roleValue = roleInput.value;
    const selectedFiles = Array.from(fileInput.selectedOptions).map((option) => option.value);
    const title = noticeTitle.value.trim();
    const message = noticeMessage.value.trim();
    const body = {
      users,
      tagMode: tagModeInput.value,
      visibleFileMode: fileModeInput.value
    };

    if (roleValue) body.role = roleValue === "clear" ? null : roleValue;
    if (clearUserTagsInput.checked) {
      body.tags = [];
      body.tagMode = "replace";
    } else if (tagInput.value.trim()) {
      body.tags = parseTags(tagInput.value);
    }
    if (clearVisibleTagsInput.checked) {
      body.visibleTags = [];
      body.visibleTagMode = "replace";
    } else if (visibleTagInput.value.trim()) {
      body.visibleTags = parseTags(visibleTagInput.value);
      body.visibleTagMode = visibleTagModeInput.value;
    }
    if (clearVisibleFilesInput.checked) {
      body.visibleFileIds = [];
      body.visibleFileMode = "replace";
    } else if (selectedFiles.length) {
      body.visibleFileIds = selectedFiles;
    }
    if (title || message) body.notification = { title, message };

    status.textContent = "正在应用批量操作...";
    const data = await api("/api/admin/users/batch", {
      method: "POST",
      body: JSON.stringify(body)
    });
    state.users = data.users || [];
    if (data.grants) {
      for (const user of state.users) user.visibleTags = data.grants[user.name] || user.visibleTags || [];
    }
    noticeTitle.value = "";
    noticeMessage.value = "";
    if (clearUserTagsInput.checked) clearUserTagsInput.checked = false;
    if (clearVisibleTagsInput.checked) clearVisibleTagsInput.checked = false;
    if (clearVisibleFilesInput.checked) clearVisibleFilesInput.checked = false;
    renderUsers();
    status.textContent = "批量操作已完成";
  }

  document.querySelector('[data-action="admin-refresh"]').addEventListener("click", () => load().catch((error) => {
    status.textContent = error.message;
  }));
  form.addEventListener("submit", (event) => applyBatch(event).catch((error) => {
    status.textContent = error.message;
  }));

  load().catch((error) => {
    status.textContent = error.message;
  });
})();
`;

const shareClientScript = String.raw`
(() => {
  const code = document.querySelector("[data-share-code]").dataset.shareCode;
  const list = document.getElementById("share-file-list");
  const status = document.getElementById("share-status");
  const form = document.getElementById("share-password-form");
  const input = document.getElementById("share-password-input");
  const expiryNote = document.getElementById("share-expiry-note");
  const allButton = document.querySelector('[data-action="share-download-all"]');
  const menu = document.getElementById("share-context-menu");
  const state = { files: [], password: "", contextId: "", downloadTicket: "", ticketExpiresAt: 0, downloading: false };

  async function fetchShare() {
    status.textContent = "正在读取分享...";
    const path = "/api/shares/" + encodeURIComponent(code);
    const response = state.password
      ? await fetch(path + "/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: state.password })
        })
      : await fetch(path);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "分享读取失败");

    if (data.expiresAt) {
      expiryNote.textContent = "有效期至 " + new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(data.expiresAt));
    } else {
      expiryNote.textContent = "";
    }

    if (data.locked) {
      form.hidden = false;
      state.files = [];
      state.downloadTicket = "";
      state.ticketExpiresAt = 0;
      render();
      status.textContent = "该分享需要密码";
      allButton.disabled = true;
      return;
    }

    form.hidden = true;
    state.files = data.files || [];
    state.downloadTicket = data.downloadTicket || "";
    state.ticketExpiresAt = Date.now() + Math.max(Number(data.downloadTicketExpiresIn || 0) - 15, 0) * 1000;
    render();
  }

  function formatDate(value) {
    if (!value) return "从未";
    return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
  }

  function formatSize(bytes) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let size = bytes || 0;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    return size.toFixed(size >= 10 || unit === 0 ? 0 : 1) + " " + units[unit];
  }

  function render() {
    list.innerHTML = "";
    for (const file of state.files) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "file-row";
      row.dataset.id = file.id;
      row.innerHTML =
        '<span class="file-name">' +
          '<span class="file-icon">FILE</span>' +
          '<span>' +
            '<strong class="file-title"></strong>' +
            '<small class="file-size">' + formatSize(file.size) + '</small>' +
          '</span>' +
        '</span>' +
        '<span class="file-description"></span>' +
        '<span class="file-tags"></span>' +
        '<span>' + formatDate(file.uploadedAt) + '</span>' +
        '<span>' + formatDate(file.lastDownloadedAt) + '</span>' +
        '<span>' + file.downloadCount + '</span>';
      row.querySelector(".file-title").textContent = file.name;
      row.querySelector(".file-description").textContent = file.description || "无描述";
      const tags = row.querySelector(".file-tags");
      if (file.tags?.length) {
        for (const tag of file.tags) {
          const chip = document.createElement("span");
          chip.className = "tag-chip";
          chip.textContent = tag;
          tags.append(chip);
        }
      } else {
        const empty = document.createElement("span");
        empty.className = "tag-empty";
        empty.textContent = "无标签";
        tags.append(empty);
      }
      row.addEventListener("click", () => download([file.id]).catch((error) => {
        state.downloading = false;
        allButton.disabled = state.files.length === 0;
        status.textContent = error.message;
      }));
      row.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        state.contextId = file.id;
        showMenu(event.clientX, event.clientY);
      });
      list.append(row);
    }
    status.textContent = state.files.length ? state.files.length + " 个文件" : "分享中没有可下载文件";
    allButton.disabled = state.files.length === 0 || state.downloading;
  }

  function hideMenu() {
    state.contextId = "";
    menu.hidden = true;
  }

  function showMenu(x, y) {
    menu.hidden = false;
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - rect.width - 10) + "px";
    menu.style.top = Math.min(y, window.innerHeight - rect.height - 10) + "px";
  }

  function triggerDownload(url) {
    const link = document.createElement("a");
    link.href = url;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
  }

  async function ensureDownloadTicket() {
    if (state.downloadTicket && Date.now() < state.ticketExpiresAt) return state.downloadTicket;
    const response = await fetch("/api/shares/" + encodeURIComponent(code) + "/download-ticket", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: state.password })
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || "下载失败");
    }
    const data = await response.json().catch(() => ({}));
    if (!data.ticket) throw new Error("下载链接生成失败");
    state.downloadTicket = data.ticket;
    state.ticketExpiresAt = Date.now() + Math.max(Number(data.expiresIn || 0) - 15, 0) * 1000;
    return state.downloadTicket;
  }

  function downloadUrl(ids, ticket) {
    const url = new URL("/api/shares/" + encodeURIComponent(code) + "/download", location.origin);
    url.searchParams.set("ticket", ticket);
    for (const id of ids) url.searchParams.append("id", id);
    return url.toString();
  }

  async function download(ids) {
    if (!ids.length || state.downloading) return;
    hideMenu();
    state.downloading = true;
    allButton.disabled = true;
    status.textContent = ids.length === 1 ? "下载已开始" : "开始打包 " + ids.length + " 个文件";
    const ticket = await ensureDownloadTicket();
    triggerDownload(downloadUrl(ids, ticket));
    status.textContent = "下载已开始";
    setTimeout(() => {
      state.downloading = false;
      allButton.disabled = state.files.length === 0;
      fetchShare().catch((error) => {
        status.textContent = error.message;
      });
    }, 1200);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    state.password = input.value;
    fetchShare().catch((error) => {
      status.textContent = error.message;
    });
  });

  allButton.addEventListener("click", () => download(state.files.map((file) => file.id)).catch((error) => {
    state.downloading = false;
    allButton.disabled = state.files.length === 0;
    status.textContent = error.message;
  }));

  menu.addEventListener("click", (event) => {
    const action = event.target.closest("button")?.dataset.shareMenuAction;
    if (action !== "download" || !state.contextId) return;
    download([state.contextId]).catch((error) => {
      state.downloading = false;
      allButton.disabled = state.files.length === 0;
      status.textContent = error.message;
    });
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".context-menu")) hideMenu();
  });

  fetchShare().catch((error) => {
    status.textContent = error.message;
  });
})();
`;

export default app;
