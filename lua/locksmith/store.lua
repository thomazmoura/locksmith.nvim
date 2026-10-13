-- Files of locksmith: the header (store.json: KDF parameters and the wrapped data key), the
-- sealed items and caches. Every write goes to a temporary file created with mode 0600, is
-- fsynced and renamed over the target; store.json is only rewritten under a lock file.
--
--   $XDG_DATA_HOME/locksmith/store.json                    header
--   $XDG_DATA_HOME/locksmith/items/<namespace>/<name>.json  secret or config
--   $XDG_CACHE_HOME/locksmith/<namespace>/<name>.json       cache
local M = {}

local crypto = require("locksmith.crypto")

M.FORMAT = "locksmith:1"
M.LOCK_STALE = 30 -- seconds
M.LOCK_WAIT = 5000 -- ms

--- Tests: before_rename(tmp, path) runs between the write and the rename (an error there is
--- a crash: the temporary file is left behind)
M.hooks = {}

local DIR_MODE = tonumber("700", 8)
local FILE_MODE = tonumber("600", 8)
local KDF_LIMITS = { t = { 1, 64 }, m = { 8, 4 * 1024 * 1024 }, p = { 1, 64 } }

local b64, unb64 = vim.base64.encode, vim.base64.decode

-- Paths and names --------------------------------------------------------------------------

local function xdg(variable, default)
  local value = vim.env[variable]
  if not value or value == "" then
    value = (vim.env.HOME or vim.uv.os_homedir()) .. "/" .. default
  end
  return value
end

function M.data_dir()
  return xdg("XDG_DATA_HOME", ".local/share") .. "/locksmith"
end

function M.cache_dir()
  return xdg("XDG_CACHE_HOME", ".cache") .. "/locksmith"
end

function M.header_path()
  return M.data_dir() .. "/store.json"
end

--- Namespaces and item names: letters, digits, ".", "_", "-" (not only dots: no "..")
function M.valid_name(name)
  return type(name) == "string" and #name <= 128 and name:match("^[%w._-]+$") ~= nil and not name:match("^%.+$")
end

function M.check_name(what, name)
  if not M.valid_name(name) then
    error(("locksmith: invalid %s %s (letters, digits, '.', '_' and '-')"):format(what, vim.inspect(name)), 3)
  end
end

--- Directory of a namespace: "items" (secrets and config) or "cache"
function M.namespace_dir(area, namespace)
  if area == "cache" then
    return M.cache_dir() .. "/" .. namespace
  end
  return M.data_dir() .. "/items/" .. namespace
end

function M.item_path(area, namespace, name)
  return M.namespace_dir(area, namespace) .. "/" .. name .. ".json"
end

local function area_of(kind)
  return kind == "cache" and "cache" or "items"
end

-- Files ------------------------------------------------------------------------------------

--- Create `dir` and its parents up to `root` with mode 0700 (root's parents with mkdir -p)
local function mkdirs(root, dir)
  if not vim.uv.fs_stat(root) then
    vim.fn.mkdir(root, "p", DIR_MODE)
  end
  vim.uv.fs_chmod(root, DIR_MODE)
  local path = root
  for part in dir:sub(#root + 2):gmatch("[^/]+") do
    path = path .. "/" .. part
    if not vim.uv.fs_stat(path) then
      local ok, err = vim.uv.fs_mkdir(path, DIR_MODE)
      if not ok and not vim.uv.fs_stat(path) then
        error(("locksmith: cannot create %s: %s"):format(path, err))
      end
    end
  end
end

local function root_of(path)
  local cache = M.cache_dir()
  return path:sub(1, #cache) == cache and cache or M.data_dir()
end

local function fsync_dir(dir)
  local fd = vim.uv.fs_open(dir, "r", 0)
  if fd then
    vim.uv.fs_fsync(fd)
    vim.uv.fs_close(fd)
  end
end

local function unique()
  return vim.uv.os_getpid() .. "-" .. vim.uv.hrtime() .. "-" .. math.random(1e9)
end

--- Write `content` to a new file `path` (mode 0600 from its creation), fsynced
local function write_new(path, content)
  local fd, err = vim.uv.fs_open(path, "wx", FILE_MODE)
  if not fd then
    error(("locksmith: cannot create %s: %s"):format(path, err))
  end
  local written, write_err = vim.uv.fs_write(fd, content, 0)
  local synced = written == #content and vim.uv.fs_fsync(fd)
  vim.uv.fs_close(fd)
  if not synced then
    vim.uv.fs_unlink(path)
    error(("locksmith: cannot write %s: %s"):format(path, write_err or "short write"))
  end
end

--- Replace `path` with `content` atomically (temporary file, fsync, rename)
function M.write_atomic(path, content)
  local dir = vim.fs.dirname(path)
  mkdirs(root_of(path), dir)
  local tmp = ("%s/.%s.%s.tmp"):format(dir, vim.fs.basename(path), unique())
  write_new(tmp, content)
  if M.hooks.before_rename then
    M.hooks.before_rename(tmp, path)
  end
  local ok, err = vim.uv.fs_rename(tmp, path)
  if not ok then
    vim.uv.fs_unlink(tmp)
    error(("locksmith: cannot write %s: %s"):format(path, err))
  end
  fsync_dir(dir)
end

function M.read_file(path)
  local fd = vim.uv.fs_open(path, "r", 0)
  if not fd then
    return nil
  end
  local stat = vim.uv.fs_fstat(fd)
  local content = stat and vim.uv.fs_read(fd, stat.size, 0)
  vim.uv.fs_close(fd)
  return content
end

local function remove(path)
  if vim.uv.fs_stat(path) then
    vim.fn.delete(path, "rf")
  end
end

--- Run fn() holding the lock file of store.json (created with O_EXCL; one older than
--- M.LOCK_STALE seconds is left over by a crash and removed). Errors propagate
function M.with_lock(fn)
  mkdirs(M.data_dir(), M.data_dir())
  local lock = M.header_path() .. ".lock"
  local deadline = vim.uv.now() + M.LOCK_WAIT
  while true do
    local fd = vim.uv.fs_open(lock, "wx", FILE_MODE)
    if fd then
      vim.uv.fs_write(fd, tostring(vim.uv.os_getpid()), 0)
      vim.uv.fs_close(fd)
      break
    end
    local stat = vim.uv.fs_stat(lock)
    if stat and os.time() - stat.mtime.sec > M.LOCK_STALE then
      vim.uv.fs_unlink(lock)
    elseif vim.uv.now() > deadline then
      error("locksmith: " .. lock .. " is held by another process")
    else
      vim.uv.sleep(20)
      vim.uv.update_time()
    end
  end
  local result = { pcall(fn) }
  vim.uv.fs_unlink(lock)
  if not result[1] then
    error(result[2], 0)
  end
  return unpack(result, 2, table.maxn(result))
end

-- Header -----------------------------------------------------------------------------------

local function now()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

--- Check the KDF parameters (bounds: a header may not make unlocking take forever)
function M.check_kdf(kdf)
  for key, range in pairs(KDF_LIMITS) do
    local value = kdf[key]
    if type(value) ~= "number" or value ~= math.floor(value) or value < range[1] or value > range[2] then
      return false, ("invalid KDF parameter %s = %s"):format(key, tostring(value))
    end
  end
  if kdf.m < 8 * kdf.p then
    return false, "invalid KDF parameters: m must be at least 8 * p KiB"
  end
  return true, nil
end

--- The header, nil when there is no store
---@return table|nil header
---@return string|nil err: the header is there but unreadable
function M.read_header()
  local content = M.read_file(M.header_path())
  if not content then
    return nil, nil
  end
  local ok, header = pcall(vim.json.decode, content)
  if not ok or type(header) ~= "table" then
    return nil, M.header_path() .. " is not valid JSON"
  end
  if header.format ~= M.FORMAT then
    return nil, ("%s: unsupported format %s"):format(M.header_path(), tostring(header.format))
  end
  local kdf, wrapped = header.kdf, header.wrapped_dek
  if type(kdf) ~= "table" or kdf.alg ~= "argon2id" or type(kdf.salt) ~= "string" then
    return nil, M.header_path() .. ": unsupported KDF"
  end
  local valid, err = M.check_kdf(kdf)
  if not valid then
    return nil, M.header_path() .. ": " .. err
  end
  if type(wrapped) ~= "table" or type(header.dek_generation) ~= "number" or type(header.id) ~= "string" then
    return nil, M.header_path() .. " is incomplete"
  end
  return header, nil
end

--- A new header (not written): random salt and store id, generation 1, no wrapped key yet
function M.new_header(kdf)
  local time = now()
  return {
    format = M.FORMAT,
    id = b64(crypto.random(16)),
    kdf = { alg = "argon2id", t = kdf.t, m = kdf.m, p = kdf.p, salt = b64(crypto.random(16)) },
    dek_generation = 1,
    wrapped_dek = vim.empty_dict(),
    created = time,
    changed = time,
  }
end

--- New KDF parameters and salt (a password change): the wrapped key must be wrapped again
function M.set_kdf(header, kdf)
  header.kdf = { alg = "argon2id", t = kdf.t, m = kdf.m, p = kdf.p, salt = b64(crypto.random(16)) }
  header.changed = now()
end

--- AAD of the wrapped key: what the header says about it, so that none of it (KDF
--- parameters, salt, generation, store) can be changed without breaking the unwrap
function M.header_aad(header)
  local kdf = header.kdf
  return table.concat({
    header.format,
    "dek",
    header.id,
    kdf.alg,
    "t=" .. kdf.t,
    "m=" .. kdf.m,
    "p=" .. kdf.p,
    "salt=" .. kdf.salt,
    "gen=" .. header.dek_generation,
  }, "|")
end

--- The key encryption key of `password` under the header's KDF parameters
---@return ffi.cdata*|nil kek: a key buffer, the caller wipes it
---@return string|nil err
function M.derive_kek(password, header, backend)
  local ok_salt, salt = pcall(unb64, header.kdf.salt)
  if not ok_salt or #salt < 8 then
    return nil, "invalid salt in " .. M.header_path()
  end
  local kek = crypto.key()
  local kdf = header.kdf
  local ok, err = crypto.argon2id(kek, crypto.KEY_SIZE, password, salt, { t = kdf.t, m = kdf.m, p = kdf.p, backend = backend })
  if not ok then
    return nil, err
  end
  return kek, nil
end

--- Wrap `dek` with `kek` into the header
function M.wrap_dek(kek, dek, header)
  local iv, ct, tag = crypto.seal(kek, dek, M.header_aad(header), nil, crypto.KEY_SIZE)
  header.wrapped_dek = { iv = b64(iv), ct = b64(ct), tag = b64(tag) }
end

--- Unwrap the header's key with `kek` into `dek` (a key buffer)
---@return boolean ok: false for a wrong password or an altered header
function M.unwrap_dek(kek, header, dek)
  local wrapped = header.wrapped_dek
  local ok, iv, ct, tag = pcall(function()
    return unb64(wrapped.iv), unb64(wrapped.ct), unb64(wrapped.tag)
  end)
  if not ok or #ct ~= crypto.KEY_SIZE then
    return false
  end
  return crypto.open_into(kek, iv, ct, tag, M.header_aad(header), dek) == crypto.KEY_SIZE
end

--- Write the header (caller holds the lock)
function M.write_header(header)
  M.write_atomic(M.header_path(), vim.json.encode(header) .. "\n")
end

-- Items ------------------------------------------------------------------------------------

function M.item_aad(kind, namespace, name, gen)
  return table.concat({ M.FORMAT, kind, namespace, name, tostring(gen) }, "|")
end

--- The content of a sealed file
function M.seal_item(dek, gen, kind, namespace, name, plaintext)
  local iv, ct, tag = crypto.seal(dek, plaintext, M.item_aad(kind, namespace, name, gen))
  return vim.json.encode({ format = M.FORMAT, kind = kind, gen = gen, iv = b64(iv), ct = b64(ct), tag = b64(tag) }) .. "\n"
end

--- Decode a sealed file: { kind, gen, iv, ct, tag } (bytes), nil when malformed
function M.parse_item(content)
  local ok, item = pcall(vim.json.decode, content)
  if not ok or type(item) ~= "table" or item.format ~= M.FORMAT then
    return nil
  end
  if type(item.kind) ~= "string" or type(item.gen) ~= "number" then
    return nil
  end
  local decoded, iv, ct, tag = pcall(function()
    return unb64(item.iv), unb64(item.ct), unb64(item.tag)
  end)
  if not decoded then
    return nil
  end
  return { kind = item.kind, gen = item.gen, iv = iv, ct = ct, tag = tag }
end

--- Open a sealed file read from `namespace`/`name`
---@return string|nil plaintext
---@return table|nil item: { kind, gen }, also when the plaintext is nil (but malformed)
function M.open_item(dek, namespace, name, content)
  local item = M.parse_item(content)
  if not item then
    return nil, nil
  end
  local aad = M.item_aad(item.kind, namespace, name, item.gen)
  return crypto.open(dek, item.iv, item.ct, item.tag, aad), item
end

function M.read_item(area, namespace, name)
  return M.read_file(M.item_path(area, namespace, name))
end

function M.write_item(kind, namespace, name, content)
  M.write_atomic(M.item_path(area_of(kind), namespace, name), content)
end

function M.delete_item(area, namespace, name)
  vim.uv.fs_unlink(M.item_path(area, namespace, name))
end

local function names_in(dir, directories)
  local names = {}
  local handle = vim.uv.fs_scandir(dir)
  while handle do
    local entry, kind = vim.uv.fs_scandir_next(handle)
    if not entry then
      break
    end
    if directories then
      if kind == "directory" and M.valid_name(entry) then
        table.insert(names, entry)
      end
    else
      local name = entry:match("^(.+)%.json$")
      if kind == "file" and name and M.valid_name(name) then
        table.insert(names, name)
      end
    end
  end
  table.sort(names)
  return names
end

--- Item names of a namespace, sorted
function M.list(area, namespace)
  return names_in(M.namespace_dir(area, namespace), false)
end

--- Namespaces with items (or caches), sorted
function M.namespaces(area)
  local dir = area == "cache" and M.cache_dir() or (M.data_dir() .. "/items")
  local result = {}
  for _, namespace in ipairs(names_in(dir, true)) do
    if #M.list(area, namespace) > 0 then
      table.insert(result, namespace)
    end
  end
  return result
end

function M.clear_cache(namespace)
  remove(M.namespace_dir("cache", namespace))
end

function M.clear_all_caches()
  remove(M.cache_dir())
end

--- Delete everything: header, items and caches
function M.reset()
  M.with_lock(function()
    remove(M.data_dir() .. "/items")
    remove(M.cache_dir())
    vim.uv.fs_unlink(M.header_path())
  end)
end

-- Data key rotation ------------------------------------------------------------------------
-- Items sealed with a new key are staged next to their targets (".<name>.json.gen<N>"), the
-- header with the new key is written (the commit), then they are renamed over the items. A
-- crash after the commit is finished by commit_staged() at the next unlock.

local function staged_path(namespace, name, gen)
  return ("%s/.%s.json.gen%d"):format(M.namespace_dir("items", namespace), name, gen)
end

function M.stage_item(namespace, name, content, gen)
  local path = staged_path(namespace, name, gen)
  mkdirs(M.data_dir(), vim.fs.dirname(path))
  vim.uv.fs_unlink(path)
  write_new(path, content)
end

local function each_staged(fn)
  local dir = M.data_dir() .. "/items"
  for _, namespace in ipairs(names_in(dir, true)) do
    local handle = vim.uv.fs_scandir(M.namespace_dir("items", namespace))
    while handle do
      local entry = vim.uv.fs_scandir_next(handle)
      if not entry then
        break
      end
      local name, gen = entry:match("^%.(.+)%.json%.gen(%d+)$")
      if name then
        fn(namespace, name, tonumber(gen))
      end
    end
  end
end

--- Rename the items staged for generation `gen` over their targets; drop any other staged one
function M.commit_staged(gen)
  each_staged(function(namespace, name, staged_gen)
    local path = staged_path(namespace, name, staged_gen)
    if staged_gen == gen then
      vim.uv.fs_rename(path, M.item_path("items", namespace, name))
    else
      vim.uv.fs_unlink(path)
    end
  end)
end

function M.discard_staged()
  each_staged(function(namespace, name, gen)
    vim.uv.fs_unlink(staged_path(namespace, name, gen))
  end)
end

return M
