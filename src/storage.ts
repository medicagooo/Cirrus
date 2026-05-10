import type { ObjectStorage } from "./object-storage";

const OBJECT_PREFIX = "objects/";
const META_PREFIX = "meta/";
const SHARE_PREFIX = "shares/";
const DIRECT_MESSAGES_PREFIX = "messages/";
const PERMISSIONS_KEY = "permissions/tag-grants.json";
const USER_PROFILES_KEY = "permissions/user-profiles.json";
const USER_PASSWORDS_KEY = "accounts/passwords.json";
const PASSWORD_HASH_ITERATIONS = 100_000;

export interface DriveFileMeta {
  id: string;
  name: string;
  description: string;
  tags: string[];
  owner: string;
  size: number;
  contentType: string;
  uploadedAt: string;
  expiresAt: string | null;
  lastDownloadedAt: string | null;
  downloadCount: number;
}

export interface ShareRecord {
  code: string;
  fileIds: string[];
  passwordHash: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export interface CreateShareInput {
  fileIds: string[];
  code?: string;
  password?: string;
  expiresAt?: string | null;
}

export interface SetUserVisibleTagsOptions {
  allowedUsers?: string[];
}

export type UserTagGrants = Record<string, string[]>;

export type ManagedUserRole = "admin" | "user";
export type MergeMode = "replace" | "add" | "remove";

export interface UpdateUserTagGrantsInput {
  users: string[];
  tags: string[];
  mode?: MergeMode;
  allowedUsers?: string[];
}

export interface UserNotification {
  id: string;
  title: string;
  message: string;
  from: string;
  createdAt: string;
  readAt: string | null;
}

export interface UserProfile {
  nickname: string;
  avatar: string;
  status: string;
  role: ManagedUserRole | null;
  tags: string[];
  visibleFileIds: string[];
  friends: string[];
  notifications: UserNotification[];
  updatedAt: string;
}

export type UserProfiles = Record<string, UserProfile>;

export interface UpdateUserProfilesInput {
  users: string[];
  role?: ManagedUserRole | null;
  tags?: string[];
  tagMode?: MergeMode;
  visibleFileIds?: string[];
  visibleFileMode?: MergeMode;
  notification?: {
    title?: string;
    message?: string;
    from?: string;
  } | null;
  allowedUsers?: string[];
}

export interface UpdateOwnUserProfileInput {
  nickname?: unknown;
  avatar?: unknown;
  status?: unknown;
  allowedUsers?: string[];
}

export interface UserPasswordCredential {
  passwordHash: string;
  updatedAt: string;
}

export type UserPasswordCredentials = Record<string, UserPasswordCredential>;

export interface StoredUserAccount {
  name: string;
  role: ManagedUserRole;
  createdAt: string;
}

export type StoredUserAccounts = Record<string, StoredUserAccount>;

export interface DirectMessage {
  id: string;
  from: string;
  to: string;
  message: string;
  fileIds: string[];
  createdAt: string;
}

export interface SendDirectMessageInput {
  from: string;
  to: string;
  message?: unknown;
  fileIds?: unknown;
  allowedUsers?: string[];
}

export class AppError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

export function objectKey(id: string) {
  return `${OBJECT_PREFIX}${id}`;
}

function metaKey(id: string) {
  return `${META_PREFIX}${id}.json`;
}

function shareKey(code: string) {
  return `${SHARE_PREFIX}${code}.json`;
}

function directConversationKey(userA: string, userB: string) {
  return `${DIRECT_MESSAGES_PREFIX}${conversationId(userA, userB)}.json`;
}

export function cleanFileName(name: string) {
  const cleaned = name
    .replace(/[\/\\]+/g, "_")
    .replace(/[\u0000-\u001f\u007f]+/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 180);

  if (!cleaned || cleaned === "." || cleaned === "..") return "untitled";
  return cleaned;
}

export function cleanDescription(value: unknown) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 500);
}

export function cleanText(value: unknown, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

export function cleanNickname(value: unknown) {
  return cleanText(value, 32);
}

export function cleanAvatar(value: unknown) {
  if (typeof value !== "string") return "";
  const avatar = value.trim();
  if (!avatar) return "";
  if (avatar.length > 50_000) return "";
  if (!/^data:image\/(?:png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(avatar)) return "";
  return avatar;
}

export function cleanStatus(value: unknown) {
  return cleanText(value, 80);
}

export function cleanTags(value: unknown) {
  const rawTags = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/[,，\n]+/)
      : [];
  const seen = new Set<string>();
  const tags: string[] = [];

  for (const raw of rawTags) {
    if (typeof raw !== "string") continue;
    const tag = raw.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 32);
    if (!tag) continue;

    const key = tag.toLocaleLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    tags.push(tag);
    if (tags.length >= 20) break;
  }

  return tags;
}

function cleanOwner(value: unknown) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f:,\s]+/g, "").trim().slice(0, 64);
}

export function cleanUserName(value: unknown) {
  if (typeof value !== "string") return "";
  const user = value.trim();
  return /^[A-Za-z0-9_.-]{1,64}$/.test(user) ? user : "";
}

function cleanRole(value: unknown): ManagedUserRole | null {
  return value === "admin" || value === "user" ? value : null;
}

function cleanUuidList(value: unknown) {
  const values = Array.isArray(value) ? value : [];
  const seen = new Set<string>();
  const ids: string[] = [];
  for (const id of values) {
    if (typeof id !== "string" || !isUuid(id) || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= 1000) break;
  }
  return ids;
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function cleanUserList(value: unknown, allowed?: Set<string>) {
  const values = Array.isArray(value) ? value : [];
  const seen = new Set<string>();
  const users: string[] = [];
  for (const raw of values) {
    const user = cleanUserName(raw);
    if (!user || seen.has(user) || (allowed && !allowed.has(user))) continue;
    seen.add(user);
    users.push(user);
    if (users.length >= 1000) break;
  }
  return users;
}

function conversationId(userA: string, userB: string) {
  return [cleanUserName(userA), cleanUserName(userB)].sort((a, b) => a.localeCompare(b)).join("__");
}

export function isExpired(expiresAt: string | null | undefined, now = Date.now()) {
  if (!expiresAt) return false;
  const time = Date.parse(expiresAt);
  return Number.isFinite(time) && time <= now;
}

export function parseOptionalDate(value: unknown) {
  if (typeof value !== "string" || !value.trim()) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new AppError("时间格式无效");
  }
  return date.toISOString();
}

function cleanContentType(value: unknown) {
  if (typeof value !== "string") return "application/octet-stream";
  const normalized = value.trim().toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:\s*;\s*[a-z0-9!#$&^_.+-]+=[a-z0-9!#$&^_.+-]+)*$/.test(normalized)) {
    return "application/octet-stream";
  }
  if (normalized === "text/html" || normalized === "application/xhtml+xml" || normalized === "image/svg+xml") {
    return "application/octet-stream";
  }
  return normalized.slice(0, 120);
}

async function readJson<T>(storage: ObjectStorage, key: string): Promise<T | null> {
  const object = await storage.get(key);
  if (!object) return null;

  try {
    return JSON.parse(await object.text()) as T;
  } catch {
    return null;
  }
}

async function writeJson(storage: ObjectStorage, key: string, value: unknown) {
  await storage.put(key, JSON.stringify(value), {
    contentType: "application/json; charset=utf-8",
  });
}

function normalizeFileMeta(meta: Partial<DriveFileMeta> | null) {
  if (!meta || typeof meta.id !== "string" || typeof meta.name !== "string") return null;

  return {
    id: meta.id,
    name: cleanFileName(meta.name),
    description: cleanDescription(meta.description),
    tags: cleanTags(meta.tags),
    owner: cleanOwner(meta.owner),
    size: typeof meta.size === "number" && Number.isFinite(meta.size) ? meta.size : 0,
    contentType: cleanContentType(meta.contentType),
    uploadedAt: typeof meta.uploadedAt === "string" ? meta.uploadedAt : new Date(0).toISOString(),
    expiresAt: typeof meta.expiresAt === "string" ? meta.expiresAt : null,
    lastDownloadedAt: typeof meta.lastDownloadedAt === "string" ? meta.lastDownloadedAt : null,
    downloadCount:
      typeof meta.downloadCount === "number" && Number.isFinite(meta.downloadCount) ? meta.downloadCount : 0,
  } satisfies DriveFileMeta;
}

export async function saveFileMeta(storage: ObjectStorage, meta: DriveFileMeta) {
  await writeJson(storage, metaKey(meta.id), meta);
}

export async function deleteDriveFile(storage: ObjectStorage, id: string) {
  await Promise.all([storage.delete(objectKey(id)), storage.delete(metaKey(id))]);
}

async function readFileMeta(storage: ObjectStorage, id: string) {
  return normalizeFileMeta(await readJson<Partial<DriveFileMeta>>(storage, metaKey(id)));
}

export async function getActiveFileMeta(storage: ObjectStorage, id: string) {
  const meta = await readFileMeta(storage, id);
  if (!meta) return null;

  if (isExpired(meta.expiresAt)) {
    await deleteDriveFile(storage, id);
    return null;
  }

  return meta;
}

export async function listFiles(storage: ObjectStorage) {
  const files: DriveFileMeta[] = [];
  const expiredIds: string[] = [];
  let cursor: string | undefined;

  do {
    const listed = await storage.list({
      prefix: META_PREFIX,
      cursor,
      limit: 1000,
    });

    const batch = await Promise.all(
      listed.objects.map(async (object) =>
        normalizeFileMeta(
          object.value !== undefined ? (object.value as Partial<DriveFileMeta>) : await readJson<Partial<DriveFileMeta>>(storage, object.key),
        ),
      ),
    );

    for (const meta of batch) {
      if (!meta) continue;
      if (isExpired(meta.expiresAt)) {
        expiredIds.push(meta.id);
      } else {
        files.push(meta);
      }
    }

    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  if (expiredIds.length) {
    await Promise.all(expiredIds.map((id) => deleteDriveFile(storage, id)));
  }

  return files.sort((a, b) => Date.parse(b.uploadedAt) - Date.parse(a.uploadedAt));
}

export async function createFileFromUpload(
  storage: ObjectStorage,
  file: File,
  expiresAt: string | null,
  description: string,
  tags: string[],
  owner: string,
) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const name = cleanFileName(file.name);
  const contentType = cleanContentType(file.type);

  const meta: DriveFileMeta = {
    id,
    name,
    description: cleanDescription(description),
    tags: cleanTags(tags),
    owner: cleanOwner(owner),
    size: file.size,
    contentType,
    uploadedAt: now,
    expiresAt,
    lastDownloadedAt: null,
    downloadCount: 0,
  };

  await storage.put(objectKey(id), file, {
    contentType,
  });
  await saveFileMeta(storage, meta);

  return meta;
}

export async function createFileFromCompletedUpload(
  storage: ObjectStorage,
  input: {
    id: string;
    name: string;
    size: number;
    contentType?: string;
    expiresAt: string | null;
    description: string;
    tags: string[];
    owner: string;
  },
) {
  const meta: DriveFileMeta = {
    id: input.id,
    name: cleanFileName(input.name),
    description: cleanDescription(input.description),
    tags: cleanTags(input.tags),
    owner: cleanOwner(input.owner),
    size: typeof input.size === "number" && Number.isFinite(input.size) ? input.size : 0,
    contentType: cleanContentType(input.contentType),
    uploadedAt: new Date().toISOString(),
    expiresAt: input.expiresAt,
    lastDownloadedAt: null,
    downloadCount: 0,
  };

  await saveFileMeta(storage, meta);
  return meta;
}

export async function renameFile(storage: ObjectStorage, id: string, name: string) {
  const meta = await getActiveFileMeta(storage, id);
  if (!meta) throw new AppError("文件不存在", 404);

  const next: DriveFileMeta = {
    ...meta,
    name: cleanFileName(name),
  };
  await saveFileMeta(storage, next);
  return next;
}

export async function updateFileDescription(storage: ObjectStorage, id: string, description: string) {
  const meta = await getActiveFileMeta(storage, id);
  if (!meta) throw new AppError("文件不存在", 404);

  const next: DriveFileMeta = {
    ...meta,
    description: cleanDescription(description),
  };
  await saveFileMeta(storage, next);
  return next;
}

export async function updateFileTags(storage: ObjectStorage, id: string, tags: string[]) {
  const meta = await getActiveFileMeta(storage, id);
  if (!meta) throw new AppError("文件不存在", 404);

  const next: DriveFileMeta = {
    ...meta,
    tags: cleanTags(tags),
  };
  await saveFileMeta(storage, next);
  return next;
}

export async function incrementDownload(storage: ObjectStorage, id: string) {
  const current = await getActiveFileMeta(storage, id);
  if (!current) return null;

  const next: DriveFileMeta = {
    ...current,
    downloadCount: current.downloadCount + 1,
    lastDownloadedAt: new Date().toISOString(),
  };
  await saveFileMeta(storage, next);
  return next;
}

function copyName(name: string) {
  const dot = name.lastIndexOf(".");
  if (dot > 0 && dot < name.length - 1) {
    return `${name.slice(0, dot)} - 副本${name.slice(dot)}`;
  }
  return `${name} - 副本`;
}

export async function copyFiles(storage: ObjectStorage, ids: string[], owner?: string) {
  const copied: DriveFileMeta[] = [];

  for (const id of ids) {
    const source = await getActiveFileMeta(storage, id);
    if (!source) continue;

    const object = await storage.get(objectKey(source.id));
    if (!object?.body) continue;

    const nextId = crypto.randomUUID();
    const uploadedAt = new Date().toISOString();
    const next: DriveFileMeta = {
      ...source,
      id: nextId,
      name: copyName(source.name),
      owner: owner ? cleanOwner(owner) : source.owner,
      uploadedAt,
      lastDownloadedAt: null,
      downloadCount: 0,
    };

    await storage.put(objectKey(nextId), object.body, {
      contentType: source.contentType,
    });
    await saveFileMeta(storage, next);
    copied.push(next);
  }

  return copied;
}

function normalizeUserTagGrants(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const grants: UserTagGrants = {};
  for (const [user, tags] of Object.entries(value)) {
    const normalizedUser = cleanOwner(user);
    if (!normalizedUser) continue;
    grants[normalizedUser] = cleanTags(tags);
  }

  return grants;
}

function normalizeMergeMode(value: unknown): MergeMode {
  return value === "add" || value === "remove" || value === "replace" ? value : "replace";
}

function mergeValues(current: string[], next: string[], mode: MergeMode) {
  if (mode === "replace") return next;

  const map = new Map(current.map((value) => [value.toLocaleLowerCase(), value]));
  if (mode === "add") {
    for (const value of next) {
      map.set(value.toLocaleLowerCase(), value);
    }
    return Array.from(map.values());
  }

  for (const value of next) {
    map.delete(value.toLocaleLowerCase());
  }
  return Array.from(map.values());
}

function mergeIds(current: string[], next: string[], mode: MergeMode) {
  if (mode === "replace") return next;

  const ids = new Set(current);
  if (mode === "add") {
    for (const id of next) {
      ids.add(id);
    }
    return Array.from(ids);
  }

  for (const id of next) {
    ids.delete(id);
  }
  return Array.from(ids);
}

function normalizeNotification(value: unknown): UserNotification | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const source = value as Partial<UserNotification>;
  const id = typeof source.id === "string" && isUuid(source.id) ? source.id : crypto.randomUUID();
  const title = cleanText(source.title, 80);
  const message = cleanText(source.message, 1000);
  if (!title && !message) return null;

  return {
    id,
    title: title || "通知",
    message,
    from: cleanUserName(source.from) || "admin",
    createdAt: typeof source.createdAt === "string" ? source.createdAt : new Date().toISOString(),
    readAt: typeof source.readAt === "string" ? source.readAt : null,
  };
}

function normalizeUserProfile(value: unknown): UserProfile {
  const source = value && typeof value === "object" && !Array.isArray(value) ? (value as Partial<UserProfile>) : {};
  const notifications = Array.isArray(source.notifications)
    ? source.notifications.map(normalizeNotification).filter(Boolean).slice(-100)
    : [];

  return {
    nickname: cleanNickname(source.nickname),
    avatar: cleanAvatar(source.avatar),
    status: cleanStatus(source.status),
    role: cleanRole(source.role),
    tags: cleanTags(source.tags),
    visibleFileIds: cleanUuidList(source.visibleFileIds),
    friends: cleanUserList(source.friends),
    notifications: notifications as UserNotification[],
    updatedAt: typeof source.updatedAt === "string" ? source.updatedAt : new Date(0).toISOString(),
  };
}

function normalizeUserProfiles(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const profiles: UserProfiles = {};
  for (const [user, profile] of Object.entries(value)) {
    const normalizedUser = cleanUserName(user);
    if (!normalizedUser) continue;
    profiles[normalizedUser] = normalizeUserProfile(profile);
  }

  return profiles;
}

export async function getUserTagGrants(storage: ObjectStorage) {
  return normalizeUserTagGrants(await readJson<UserTagGrants>(storage, PERMISSIONS_KEY));
}

export async function updateUserTagGrants(storage: ObjectStorage, input: UpdateUserTagGrantsInput) {
  const allowed = input.allowedUsers ? new Set(input.allowedUsers.map(cleanUserName).filter(Boolean)) : null;
  const users = Array.from(new Set(input.users.map(cleanUserName).filter(Boolean)));
  if (!users.length) throw new AppError("请选择用户");
  if (allowed && users.some((user) => !allowed.has(user))) throw new AppError("只能管理已配置用户", 400);

  const grants = await getUserTagGrants(storage);
  const tags = cleanTags(input.tags);
  const mode = normalizeMergeMode(input.mode);

  for (const user of users) {
    grants[user] = mergeValues(cleanTags(grants[user]), tags, mode).slice(0, 20);
  }

  await writeJson(storage, PERMISSIONS_KEY, grants);
  return grants;
}

export async function getUserProfiles(storage: ObjectStorage) {
  return normalizeUserProfiles(await readJson<UserProfiles>(storage, USER_PROFILES_KEY));
}

export async function saveUserProfiles(storage: ObjectStorage, profiles: UserProfiles) {
  await writeJson(storage, USER_PROFILES_KEY, normalizeUserProfiles(profiles));
}

function normalizeUserPasswordCredentials(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const credentials: UserPasswordCredentials = {};
  for (const [user, credential] of Object.entries(value)) {
    const normalizedUser = cleanUserName(user);
    if (!normalizedUser || !credential || typeof credential !== "object" || Array.isArray(credential)) continue;
    const source = credential as Partial<UserPasswordCredential>;
    if (typeof source.passwordHash !== "string" || !source.passwordHash.startsWith("pbkdf2-sha256:")) continue;
    credentials[normalizedUser] = {
      passwordHash: source.passwordHash,
      updatedAt: typeof source.updatedAt === "string" ? source.updatedAt : new Date(0).toISOString(),
    };
  }

  return credentials;
}

export async function getUserPasswordCredentials(storage: ObjectStorage) {
  return normalizeUserPasswordCredentials(await readJson<UserPasswordCredentials>(storage, USER_PASSWORDS_KEY));
}

export async function saveUserPasswordCredentials(storage: ObjectStorage, credentials: UserPasswordCredentials) {
  await writeJson(storage, USER_PASSWORDS_KEY, normalizeUserPasswordCredentials(credentials));
}

export function userAccountsFromCredentials(credentials: UserPasswordCredentials) {
  const accounts: StoredUserAccounts = {};
  for (const [user, credential] of Object.entries(credentials)) {
    const normalizedUser = cleanUserName(user);
    if (!normalizedUser) continue;
    accounts[normalizedUser] = {
      name: normalizedUser,
      role: "user",
      createdAt: credential.updatedAt,
    };
  }
  return accounts;
}

export async function createRegisteredUser(storage: ObjectStorage, user: string, password: string, existingUsers: string[]) {
  const normalizedUser = cleanUserName(user);
  if (!normalizedUser) throw new AppError("用户名只能包含字母、数字、下划线、短横线和点号，长度 1-64 位");
  const normalizedExistingUsers = existingUsers.map(cleanUserName).filter(Boolean);
  if (normalizedExistingUsers.includes(normalizedUser)) throw new AppError("用户名已存在", 409);

  const credentials = await getUserPasswordCredentials(storage);
  if (credentials[normalizedUser]) throw new AppError("用户名已存在", 409);
  const isFirstUser = normalizedExistingUsers.length === 0 && Object.keys(credentials).length === 0;

  credentials[normalizedUser] = {
    passwordHash: await hashUserPassword(normalizedUser, password),
    updatedAt: new Date().toISOString(),
  };
  await saveUserPasswordCredentials(storage, credentials);

  const profiles = await ensureUserProfiles(storage, [normalizedUser]);
  if (isFirstUser) {
    profiles[normalizedUser] = {
      ...normalizeUserProfile(profiles[normalizedUser]),
      role: "admin",
      updatedAt: new Date().toISOString(),
    };
    await saveUserProfiles(storage, profiles);
  }

  return {
    ...userAccountsFromCredentials(credentials)[normalizedUser],
    role: isFirstUser ? "admin" : "user",
  };
}

function nicknameOwner(profiles: UserProfiles, nickname: string, currentUser: string) {
  const normalized = nickname.toLocaleLowerCase();
  if (!normalized) return "";
  for (const [user, profile] of Object.entries(profiles)) {
    if (user === currentUser) continue;
    if (profile.nickname.toLocaleLowerCase() === normalized) return user;
  }
  return "";
}

export async function ensureUserProfiles(storage: ObjectStorage, users: string[]) {
  const profiles = await getUserProfiles(storage);
  const now = new Date().toISOString();
  let changed = false;

  for (const user of users.map(cleanUserName).filter(Boolean)) {
    if (profiles[user]) continue;
    profiles[user] = {
      nickname: "",
      avatar: "",
      status: "",
      role: null,
      tags: [],
      visibleFileIds: [],
      friends: [],
      notifications: [],
      updatedAt: now,
    };
    changed = true;
  }

  if (changed) await saveUserProfiles(storage, profiles);
  return profiles;
}

export async function updateOwnUserProfile(storage: ObjectStorage, user: string, input: UpdateOwnUserProfileInput) {
  const normalizedUser = cleanUserName(user);
  if (!normalizedUser) throw new AppError("用户无效");
  if (input.allowedUsers && !input.allowedUsers.map(cleanUserName).includes(normalizedUser)) {
    throw new AppError("只能修改已配置用户", 400);
  }

  const profiles = await ensureUserProfiles(storage, input.allowedUsers || [normalizedUser]);
  const current = normalizeUserProfile(profiles[normalizedUser]);
  const next: UserProfile = { ...current, updatedAt: new Date().toISOString() };

  if (input.nickname !== undefined) {
    const nickname = cleanNickname(input.nickname);
    if (!nickname) throw new AppError("请输入昵称");
    const owner = nicknameOwner(profiles, nickname, normalizedUser);
    if (owner) throw new AppError("昵称已被使用", 409);
    next.nickname = nickname;
  }
  if (input.avatar !== undefined) {
    const avatar = cleanAvatar(input.avatar);
    if (typeof input.avatar === "string" && input.avatar.trim() && !avatar) throw new AppError("头像格式无效");
    next.avatar = avatar;
  }
  if (input.status !== undefined) {
    next.status = cleanStatus(input.status);
  }

  profiles[normalizedUser] = next;
  await saveUserProfiles(storage, profiles);
  return next;
}

export async function updateUserProfiles(storage: ObjectStorage, input: UpdateUserProfilesInput) {
  const allowed = input.allowedUsers ? new Set(input.allowedUsers.map(cleanUserName).filter(Boolean)) : null;
  const users = Array.from(new Set(input.users.map(cleanUserName).filter(Boolean)));
  if (!users.length) throw new AppError("请选择用户");
  if (allowed && users.some((user) => !allowed.has(user))) throw new AppError("只能管理已配置用户", 400);

  const profiles = await getUserProfiles(storage);
  const role = input.role === null ? null : cleanRole(input.role);
  const tags = cleanTags(input.tags);
  const tagMode = normalizeMergeMode(input.tagMode);
  const visibleFileIds = cleanUuidList(input.visibleFileIds);
  const visibleFileMode = normalizeMergeMode(input.visibleFileMode);
  const notification = normalizeNotification(input.notification);
  const now = new Date().toISOString();

  for (const user of users) {
    const current = normalizeUserProfile(profiles[user]);
    const next: UserProfile = {
      ...current,
      updatedAt: now,
    };

    if (input.role !== undefined) {
      next.role = role;
    }
    if (input.tags !== undefined) {
      next.tags = mergeValues(current.tags, tags, tagMode).slice(0, 20);
    }
    if (input.visibleFileIds !== undefined) {
      next.visibleFileIds = mergeIds(current.visibleFileIds, visibleFileIds, visibleFileMode).slice(0, 1000);
    }
    if (notification) {
      next.notifications = [...current.notifications, { ...notification, id: crypto.randomUUID(), createdAt: now }].slice(-100);
    }

    profiles[user] = next;
  }

  await saveUserProfiles(storage, profiles);
  return profiles;
}

export async function addFriend(storage: ObjectStorage, user: string, friend: string, allowedUsers?: string[]) {
  const normalizedUser = cleanUserName(user);
  const normalizedFriend = cleanUserName(friend);
  if (!normalizedUser || !normalizedFriend) throw new AppError("用户无效");
  if (normalizedUser === normalizedFriend) throw new AppError("不能添加自己为好友");

  const allowed = allowedUsers ? new Set(allowedUsers.map(cleanUserName).filter(Boolean)) : null;
  if (allowed && (!allowed.has(normalizedUser) || !allowed.has(normalizedFriend))) {
    throw new AppError("只能添加已配置用户", 400);
  }

  const profiles = await ensureUserProfiles(storage, allowedUsers || [normalizedUser, normalizedFriend]);
  const current = normalizeUserProfile(profiles[normalizedUser]);
  const target = normalizeUserProfile(profiles[normalizedFriend]);
  const now = new Date().toISOString();

  current.friends = mergeValues(current.friends, [normalizedFriend], "add");
  target.friends = mergeValues(target.friends, [normalizedUser], "add");
  current.updatedAt = now;
  target.updatedAt = now;
  profiles[normalizedUser] = current;
  profiles[normalizedFriend] = target;
  await saveUserProfiles(storage, profiles);
  return profiles;
}

export async function removeFriend(storage: ObjectStorage, user: string, friend: string, allowedUsers?: string[]) {
  const normalizedUser = cleanUserName(user);
  const normalizedFriend = cleanUserName(friend);
  if (!normalizedUser || !normalizedFriend) throw new AppError("用户无效");

  const profiles = await ensureUserProfiles(storage, allowedUsers || [normalizedUser, normalizedFriend]);
  const current = normalizeUserProfile(profiles[normalizedUser]);
  const target = normalizeUserProfile(profiles[normalizedFriend]);
  const now = new Date().toISOString();

  current.friends = mergeValues(current.friends, [normalizedFriend], "remove");
  target.friends = mergeValues(target.friends, [normalizedUser], "remove");
  current.updatedAt = now;
  target.updatedAt = now;
  profiles[normalizedUser] = current;
  profiles[normalizedFriend] = target;
  await saveUserProfiles(storage, profiles);
  return profiles;
}

function normalizeDirectMessage(value: unknown): DirectMessage | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const source = value as Partial<DirectMessage>;
  const from = cleanUserName(source.from);
  const to = cleanUserName(source.to);
  const message = cleanText(source.message, 1000);
  const fileIds = cleanUuidList(source.fileIds).slice(0, 50);
  if (!from || !to || (!message && !fileIds.length)) return null;

  return {
    id: typeof source.id === "string" && isUuid(source.id) ? source.id : crypto.randomUUID(),
    from,
    to,
    message,
    fileIds,
    createdAt: typeof source.createdAt === "string" ? source.createdAt : new Date().toISOString(),
  };
}

function normalizeDirectMessages(value: unknown) {
  const rawMessages = Array.isArray(value) ? value : [];
  return rawMessages.map(normalizeDirectMessage).filter(Boolean) as DirectMessage[];
}

export async function getDirectMessages(storage: ObjectStorage, user: string, friend: string, allowedUsers?: string[]) {
  const normalizedUser = cleanUserName(user);
  const normalizedFriend = cleanUserName(friend);
  if (!normalizedUser || !normalizedFriend) throw new AppError("用户无效");

  const profiles = await ensureUserProfiles(storage, allowedUsers || [normalizedUser, normalizedFriend]);
  if (!profiles[normalizedUser].friends.includes(normalizedFriend)) {
    throw new AppError("只能查看好友私信", 403);
  }

  return normalizeDirectMessages(await readJson<DirectMessage[]>(storage, directConversationKey(normalizedUser, normalizedFriend)));
}

export async function sendDirectMessage(storage: ObjectStorage, input: SendDirectMessageInput) {
  const from = cleanUserName(input.from);
  const to = cleanUserName(input.to);
  if (!from || !to) throw new AppError("用户无效");
  if (from === to) throw new AppError("不能给自己发送私信");

  const allowed = input.allowedUsers ? new Set(input.allowedUsers.map(cleanUserName).filter(Boolean)) : null;
  if (allowed && (!allowed.has(from) || !allowed.has(to))) throw new AppError("只能给已配置用户发送私信", 400);

  const profiles = await ensureUserProfiles(storage, input.allowedUsers || [from, to]);
  if (!profiles[from].friends.includes(to)) throw new AppError("只能给好友发送私信", 403);

  const message = cleanText(input.message, 1000);
  const fileIds = cleanUuidList(input.fileIds).slice(0, 50);
  if (!message && !fileIds.length) throw new AppError("请输入私信内容或选择文件");

  const key = directConversationKey(from, to);
  const messages = normalizeDirectMessages(await readJson<DirectMessage[]>(storage, key));
  const now = new Date().toISOString();
  const next: DirectMessage = {
    id: crypto.randomUUID(),
    from,
    to,
    message,
    fileIds,
    createdAt: now,
  };

  messages.push(next);
  await writeJson(storage, key, messages.slice(-500));

  const target = normalizeUserProfile(profiles[to]);
  target.notifications = [
    ...target.notifications,
    {
      id: crypto.randomUUID(),
      title: "新的私信",
      message: fileIds.length ? `${profiles[from]?.nickname || from} 向你发送了文件` : message,
      from,
      createdAt: now,
      readAt: null,
    },
  ].slice(-100);
  target.updatedAt = now;
  profiles[to] = target;
  await saveUserProfiles(storage, profiles);

  return next;
}

export async function markUserNotificationsRead(storage: ObjectStorage, user: string, ids?: string[]) {
  const normalizedUser = cleanUserName(user);
  if (!normalizedUser) throw new AppError("用户无效");

  const profiles = await getUserProfiles(storage);
  const profile = normalizeUserProfile(profiles[normalizedUser]);
  const targetIds = ids && ids.length ? new Set(cleanUuidList(ids)) : null;
  const now = new Date().toISOString();
  let changed = false;

  profile.notifications = profile.notifications.map((notification) => {
    if (notification.readAt || (targetIds && !targetIds.has(notification.id))) return notification;
    changed = true;
    return { ...notification, readAt: now };
  });

  if (changed) {
    profile.updatedAt = now;
    profiles[normalizedUser] = profile;
    await saveUserProfiles(storage, profiles);
  }

  return profile.notifications;
}

export async function setUserVisibleTags(
  storage: ObjectStorage,
  user: string,
  tags: string[],
  options: SetUserVisibleTagsOptions = {},
) {
  const normalizedUser = cleanOwner(user);
  if (!normalizedUser) throw new AppError("用户无效");
  if (options.allowedUsers && !options.allowedUsers.includes(normalizedUser)) {
    throw new AppError("只能为已配置的普通用户设置权限", 400);
  }

  const grants = await getUserTagGrants(storage);
  grants[normalizedUser] = cleanTags(tags);
  await writeJson(storage, PERMISSIONS_KEY, grants);
  return grants[normalizedUser];
}

function normalizeShareCode(value: string) {
  const code = value.trim();
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(code)) {
    throw new AppError("分享码只能包含字母、数字、下划线和短横线，长度 4-64 位");
  }
  return code;
}

function randomShareCode(length = 10) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

async function sha256Hex(input: string) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(code: string, password: string) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const iterations = PASSWORD_HASH_ITERATIONS;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(`${code}:${password}`), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    key,
    256,
  );

  return `pbkdf2-sha256:${iterations}:${base64Url(salt)}:${base64Url(new Uint8Array(bits))}`;
}

export async function hashUserPassword(user: string, password: string) {
  const normalizedUser = cleanUserName(user);
  const normalizedPassword = cleanText(password, 512);
  if (!normalizedUser) throw new AppError("用户无效");
  if (normalizedPassword.length < 6) throw new AppError("密码至少需要 6 位");
  return hashPassword(`user:${normalizedUser}`, normalizedPassword);
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

function timingSafeBytesEqual(a: Uint8Array, b: Uint8Array) {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    diff |= (a[index] || 0) ^ (b[index] || 0);
  }
  return diff === 0;
}

export async function createShare(storage: ObjectStorage, input: CreateShareInput) {
  const fileIds = Array.from(new Set(input.fileIds.filter(Boolean)));
  if (!fileIds.length) throw new AppError("请选择要分享的文件");

  const activeFiles = (
    await Promise.all(fileIds.map((id) => getActiveFileMeta(storage, id)))
  ).filter(Boolean) as DriveFileMeta[];
  if (!activeFiles.length) throw new AppError("可分享的文件不存在", 404);

  let code = input.code ? normalizeShareCode(input.code) : randomShareCode();
  if (input.code && (await readJson<ShareRecord>(storage, shareKey(code)))) {
    throw new AppError("分享码已存在，请换一个");
  }

  while (!input.code && (await readJson<ShareRecord>(storage, shareKey(code)))) {
    code = randomShareCode();
  }

  const password = input.password?.trim().slice(0, 256);
  const share: ShareRecord = {
    code,
    fileIds: activeFiles.map((file) => file.id),
    passwordHash: password ? await hashPassword(code, password) : null,
    createdAt: new Date().toISOString(),
    expiresAt: input.expiresAt ?? null,
  };

  await writeJson(storage, shareKey(code), share);
  return share;
}

export async function getShare(storage: ObjectStorage, code: string) {
  const normalized = normalizeShareCode(code);
  const share = await readJson<ShareRecord>(storage, shareKey(normalized));
  if (!share) return null;

  if (isExpired(share.expiresAt)) {
    await storage.delete(shareKey(normalized));
    return null;
  }

  return share;
}

export async function verifySharePassword(share: ShareRecord, password: string | null | undefined) {
  if (!share.passwordHash) return true;
  const normalizedPassword = cleanText(password, 512);
  if (!normalizedPassword) return false;

  if (!share.passwordHash.startsWith("pbkdf2-sha256:")) {
    return (await sha256Hex(`${share.code}:${normalizedPassword}`)) === share.passwordHash;
  }

  const [, iterationsValue, saltValue, hashValue] = share.passwordHash.split(":");
  const iterations = Number(iterationsValue);
  if (!Number.isSafeInteger(iterations) || iterations < 10_000 || !saltValue || !hashValue) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(`${share.code}:${normalizedPassword}`),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const expected = base64UrlToBytes(hashValue);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: base64UrlToBytes(saltValue),
      iterations,
    },
    key,
    expected.length * 8,
  );

  return timingSafeBytesEqual(new Uint8Array(bits), expected);
}

export async function verifyUserPasswordHash(user: string, passwordHash: string, password: string | null | undefined) {
  const normalizedUser = cleanUserName(user);
  const normalizedPassword = cleanText(password, 512);
  if (!normalizedUser || !normalizedPassword || !passwordHash.startsWith("pbkdf2-sha256:")) return false;

  const [, iterationsValue, saltValue, hashValue] = passwordHash.split(":");
  const iterations = Number(iterationsValue);
  if (!Number.isSafeInteger(iterations) || iterations < 10_000 || !saltValue || !hashValue) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(`user:${normalizedUser}:${normalizedPassword}`),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const expected = base64UrlToBytes(hashValue);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: base64UrlToBytes(saltValue),
      iterations,
    },
    key,
    expected.length * 8,
  );

  return timingSafeBytesEqual(new Uint8Array(bits), expected);
}

export async function updateUserPassword(
  storage: ObjectStorage,
  user: string,
  newPassword: string,
  allowedUsers?: string[],
) {
  const normalizedUser = cleanUserName(user);
  if (!normalizedUser) throw new AppError("用户无效");
  if (allowedUsers && !allowedUsers.map(cleanUserName).includes(normalizedUser)) {
    throw new AppError("只能修改已配置用户", 400);
  }

  const credentials = await getUserPasswordCredentials(storage);
  credentials[normalizedUser] = {
    passwordHash: await hashUserPassword(normalizedUser, newPassword),
    updatedAt: new Date().toISOString(),
  };
  await saveUserPasswordCredentials(storage, credentials);
  return credentials[normalizedUser];
}

export async function resolveShareFiles(storage: ObjectStorage, share: ShareRecord) {
  return (
    await Promise.all(share.fileIds.map((id) => getActiveFileMeta(storage, id)))
  ).filter(Boolean) as DriveFileMeta[];
}

export async function resolveShareFilesByIds(storage: ObjectStorage, share: ShareRecord, ids: string[]) {
  const allowed = new Set(share.fileIds);
  return (
    await Promise.all(ids.map((id) => (allowed.has(id) ? getActiveFileMeta(storage, id) : null)))
  ).filter(Boolean) as DriveFileMeta[];
}
