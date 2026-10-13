-- locksmith: an encrypted store for Neovim plugins (secrets, config, caches), unlocked once
-- per Neovim with a password that is never written anywhere, not even encrypted.
--
-- Envelope encryption: Argon2id(password) is the key encryption key, which wraps a random data
-- key (in store.json); the data key seals every item with AES-256-GCM. Changing the password
-- re-wraps the data key only. The data key lives in this module (one copy per Neovim, shared
-- by every plugin through require) in a buffer zeroed by lock().
--
-- Every call that may need the key is asynchronous: callback(value, err) on the main loop.
local M = {}

local store = require("locksmith.store")
local prompt = require("locksmith.prompt")

local DECLINED = "locked: the password was not entered (:Locksmith unlock to enter it)"

local config = {
  harden = true,
  kdf = { t = 3, m = 262144, p = 4 },
  backend = nil, -- Argon2id backend: "libargon2" or "openssl", nil for the first available
}

-- Session state: the data key and what it belongs to, the callbacks waiting for the unlock
-- in progress, the interactive flows (unlock, password change, reset) queued one at a time
local S = {
  dek = nil,
  gen = nil,
  id = nil,
  waiting = nil,
  declined = false,
  on_unlock = {},
  password_check = nil,
  hardened = false,
  busy = false,
  queue = {},
}
M._state = S

local function crypto()
  return require("locksmith.crypto")
end

local notify = prompt.notify

--- callback(...) on the main loop, later
local function later(callback, ...)
  local args = { n = select("#", ...), ... }
  vim.schedule(function()
    callback(unpack(args, 1, args.n))
  end)
end

--- Call a consumer's callback: its errors are reported, they never break a flow
local function call(fn, ...)
  local ok, err = pcall(fn, ...)
  if not ok then
    vim.schedule(function()
      error(err, 0)
    end)
  end
end

--- Run fn(done) when no other interactive flow is running
local function flow(fn)
  if S.busy then
    return table.insert(S.queue, fn)
  end
  S.busy = true
  fn(function()
    S.busy = false
    local next_flow = table.remove(S.queue, 1)
    if next_flow then
      vim.schedule(function()
        flow(next_flow)
      end)
    end
  end)
end

local function ask(message, kind, callback, choices)
  prompt.ask(message, { kind = kind, choices = choices }, callback)
end

-- Keys -------------------------------------------------------------------------------------

local function forget_keys()
  if S.dek then
    crypto().wipe(S.dek)
  end
  S.dek, S.gen, S.id = nil, nil, nil
end

--- Is the data key in memory still the store's? (another Neovim may have rotated it, or
--- reset the store). A stale one is forgotten
---@return boolean
local function current()
  if not S.dek then
    return false
  end
  local header = store.read_header()
  if not header or header.id ~= S.id or header.dek_generation ~= S.gen then
    forget_keys()
    return false
  end
  return true
end

--- The data key of `header` opened with `password`, in a new key buffer
---@return ffi.cdata*|nil dek: nil for a wrong password
---@return string|nil err: the KDF failed
local function open_dek(header, password)
  local kek, err = store.derive_kek(password, header, config.backend)
  if not kek then
    return nil, err
  end
  local dek = crypto().key()
  local ok = store.unwrap_dek(kek, header, dek)
  crypto().wipe(kek)
  if not ok then
    return nil, nil
  end
  return dek, nil
end

--- Make `dek` the session's key
local function adopt(dek, header)
  if S.dek and S.dek ~= dek then
    crypto().wipe(S.dek)
  end
  S.dek, S.gen, S.id = dek, header.dek_generation, header.id
  -- A data key rotation interrupted after its commit: its items are renamed in now
  store.commit_staged(S.gen)
end

--- After an unlock: hardening, then the password to the on_unlock functions (once each)
local function unlocked_with(password)
  S.declined = false
  if config.harden and not S.hardened then
    S.hardened = true
    if not crypto().harden() then
      notify("could not make this Neovim non-dumpable (prctl failed)", vim.log.levels.WARN)
    end
  end
  local consumers = S.on_unlock
  S.on_unlock = {}
  for _, fn in ipairs(consumers) do
    call(fn, password)
  end
  -- The password is a Lua string, which cannot be wiped: dropped by every caller by now
  vim.schedule(function()
    collectgarbage("collect")
  end)
end

--- A new password, typed twice, then checked by set_password_check() when there is one.
--- callback(password or nil, err)
local function ask_new(label, callback, attempt)
  attempt = attempt or 1
  ask(label, "password", function(password)
    if not password then
      return callback(nil, "no password entered")
    end
    ask("Type it again: ", "password", function(again)
      if again ~= password then
        if attempt < 2 then
          notify("the passwords do not match, try again", vim.log.levels.WARN)
          return ask_new(label, callback, attempt + 1)
        end
        return callback(nil, "the passwords do not match")
      end
      if not S.password_check then
        return callback(password, nil)
      end
      S.password_check(password, function(ok, err)
        callback(ok and password or nil, not ok and ("password rejected: " .. (err or "check failed")) or nil)
      end)
    end)
  end)
end

--- The password just typed confirmed as the new one: by set_password_check() when there is
--- one, typed again otherwise. callback(ok, err)
local function confirm_new(password, callback)
  if S.password_check then
    return S.password_check(password, function(ok, err)
      callback(ok, not ok and ("password rejected: " .. (err or "check failed")) or nil)
    end)
  end
  ask("Type the new password again to confirm it: ", "password", function(again)
    callback(again == password, again ~= password and "the passwords do not match" or nil)
  end)
end

--- Wrap `dek` with a key derived from `password` (new salt, configured KDF parameters) and
--- write the header, unless the store changed in between
local function rewrap(dek, header, password)
  return store.with_lock(function()
    local fresh = store.read_header()
    if not fresh or fresh.id ~= header.id or fresh.dek_generation ~= header.dek_generation then
      error("locksmith: the store changed meanwhile (another Neovim?): nothing done", 0)
    end
    store.set_kdf(fresh, config.kdf)
    local kek, err = store.derive_kek(password, fresh, config.backend)
    if not kek then
      error(err, 0)
    end
    store.wrap_dek(kek, dek, fresh)
    crypto().wipe(kek)
    store.write_header(fresh)
    return fresh
  end)
end

-- Unlocking --------------------------------------------------------------------------------

--- What a reset deletes, for the confirmation
local function inventory()
  local lines = {}
  for _, namespace in ipairs(store.namespaces("items")) do
    table.insert(lines, ("  %s: %s"):format(namespace, table.concat(store.list("items", namespace), ", ")))
  end
  local caches = store.namespaces("cache")
  if #caches > 0 then
    table.insert(lines, "  caches of " .. table.concat(caches, ", "))
  end
  return #lines > 0 and table.concat(lines, "\n") or "  (no items)"
end

--- Delete everything after a confirmation. callback(ok, err)
local function confirm_reset(callback)
  local message = ("This deletes the locksmith store (%s) and everything in it:\n%s\nType yes to delete it: ")
    :format(store.data_dir(), inventory())
  ask(message, "confirm", function(answer)
    if answer ~= "yes" then
      return callback(false, "reset cancelled: nothing deleted")
    end
    forget_keys()
    local ok, err = pcall(store.reset)
    if not ok then
      return callback(false, err)
    end
    notify("the store was deleted")
    callback(true, nil)
  end)
end

local function create_store(finish)
  notify(("creating the store in %s: choose its password (it is never stored)"):format(store.data_dir()))
  ask_new("New password: ", function(password, err)
    if not password then
      return finish(false, err == "no password entered" and DECLINED or err)
    end
    local header = store.new_header(config.kdf)
    local dek = crypto().random_into(crypto().key(), crypto().KEY_SIZE)
    local kek, kdf_err = store.derive_kek(password, header, config.backend)
    if not kek then
      crypto().wipe(dek)
      return finish(false, kdf_err)
    end
    store.wrap_dek(kek, dek, header)
    crypto().wipe(kek)
    local ok, write_err = pcall(store.with_lock, function()
      if store.read_header() then
        return false
      end
      store.write_header(header)
      return true
    end)
    if not ok or not write_err then
      crypto().wipe(dek)
      if ok then
        return finish(false, "another Neovim created the store meanwhile: try again")
      end
      return finish(false, write_err)
    end
    adopt(dek, header)
    unlocked_with(password)
    finish(true, nil)
  end)
end

local attempt

--- The password typed does not open the store: a typo, a password changed elsewhere (AD
--- rotated it), or a forgotten one
local function wrong_password(header, typed, finish)
  ask("This password does not open the locksmith store.", "choice", function(choice)
    if choice == 1 then
      return attempt(header, finish)
    elseif choice == 2 then
      return ask("Previous password: ", "password", function(old)
        if not old then
          return finish(false, DECLINED)
        end
        local dek, err = open_dek(header, old)
        if err then
          return finish(false, err)
        end
        if not dek then
          notify("that password does not open the store either", vim.log.levels.WARN)
          return wrong_password(header, typed, finish)
        end
        confirm_new(typed, function(ok, confirm_err)
          if not ok then
            crypto().wipe(dek)
            return finish(false, confirm_err .. ": the store's password was not changed")
          end
          local written, fresh = pcall(rewrap, dek, header, typed)
          if not written then
            crypto().wipe(dek)
            return finish(false, fresh)
          end
          adopt(dek, fresh)
          notify("the store's password is now the new one")
          unlocked_with(typed)
          finish(true, nil)
        end)
      end)
    elseif choice == 3 then
      return confirm_reset(function(ok, err)
        if not ok then
          return finish(false, err)
        end
        create_store(finish)
      end)
    end
    finish(false, DECLINED)
  end, {
    "Retry (a typo)",
    "My password changed: type the previous one",
    "I don't remember the previous one: delete everything and start over",
  })
end

function attempt(header, finish)
  ask("locksmith password: ", "password", function(password)
    if not password then
      return finish(false, DECLINED)
    end
    local dek, err = open_dek(header, password)
    if err then
      return finish(false, err)
    end
    if not dek then
      return wrong_password(header, password, finish)
    end
    adopt(dek, header)
    unlocked_with(password)
    finish(true, nil)
  end)
end

local function run_unlock(finish)
  if current() then
    return finish(true, nil)
  end
  local available, crypto_err = crypto().available()
  if not available then
    return finish(false, crypto_err)
  end
  local backend, backend_err = crypto().argon2_backend(config.backend)
  if not backend then
    return finish(false, backend_err)
  end
  local header, err = store.read_header()
  if err then
    return finish(false, err)
  end
  if not header then
    return create_store(finish)
  end
  attempt(header, finish)
end

--- callback(ok, err) once the store is unlocked (asking the password at most once for every
--- caller waiting). After the password was not entered, fails without asking unless `force`
local function with_key(callback, force)
  if current() then
    return later(callback, true, nil)
  end
  if S.declined and not force then
    return later(callback, false, DECLINED)
  end
  if S.waiting then
    return table.insert(S.waiting, callback)
  end
  S.waiting = { callback }
  flow(function(done)
    run_unlock(function(ok, err)
      local waiting = S.waiting or {}
      S.waiting = nil
      S.declined = (not ok and err == DECLINED) or false
      done()
      for _, waiter in ipairs(waiting) do
        call(waiter, ok, err)
      end
    end)
  end)
end

-- Public API -------------------------------------------------------------------------------

--- Optional. opts = { prompt = fn, harden = true, kdf = { t, m (KiB), p }, backend = name }
function M.setup(opts)
  opts = opts or {}
  if opts.prompt ~= nil then
    M.set_prompt(opts.prompt)
  end
  if opts.harden ~= nil then
    config.harden = opts.harden
  end
  if opts.kdf then
    local kdf = vim.tbl_extend("force", config.kdf, opts.kdf)
    local ok, err = store.check_kdf(kdf)
    if not ok then
      error("locksmith.setup: " .. err, 2)
    end
    config.kdf = kdf
  end
  if opts.backend ~= nil then
    config.backend = opts.backend
  end
end

--- Unlock the store: prompts (once, shared by every caller), or creates it on first use.
--- callback(true) or callback(nil, err)
function M.unlock(callback)
  callback = callback or function() end
  with_key(function(ok, err)
    callback(ok or nil, err)
  end, true)
end

--- Forget the data key (zeroed): the next call that needs it prompts again
function M.lock()
  forget_keys()
  S.declined = false
end

---@return table { exists, unlocked, kdf, dek_generation, path, cache_path, backend, error }
function M.status()
  local header, err = store.read_header()
  local backend = crypto().argon2_backend(config.backend)
  return {
    exists = header ~= nil,
    unlocked = current(),
    kdf = header and { t = header.kdf.t, m = header.kdf.m, p = header.kdf.p } or nil,
    dek_generation = header and header.dek_generation or nil,
    created = header and header.created or nil,
    changed = header and header.changed or nil,
    path = store.data_dir(),
    cache_path = store.cache_dir(),
    backend = backend,
    error = err,
  }
end

--- Ask with fn(message, callback, opts) instead of inputsecret() / the terminal: see
--- lua/locksmith/prompt.lua. nil restores the default
function M.set_prompt(fn)
  prompt.custom = fn
end

--- fn(password, callback(ok, err)) checks a new password before the store is re-keyed with
--- it (paperboy tries it against Exchange): a typo never becomes the store's password
function M.set_password_check(fn)
  S.password_check = fn
end

--- fn(password) is called once, right after the next successful unlock: the only way the
--- password leaves locksmith. When the store is unlocked already, the password is gone: fn
--- is not called, and false is returned (the consumer asks the user itself)
---@return boolean registered
function M.on_unlock(fn)
  if current() then
    notify(
      "the store was unlocked before this plugin asked for the password, which locksmith does not keep: "
        .. "the plugin asks for it itself",
      vim.log.levels.INFO
    )
    return false
  end
  table.insert(S.on_unlock, fn)
  return true
end

local function check(namespace, name)
  store.check_name("namespace", namespace)
  store.check_name("name", name)
end

local function decrypt_error(namespace, name)
  return ("%s/%s cannot be decrypted (altered, renamed, or from another store)"):format(namespace, name)
end

--- A secret (string) or config (table). callback(value) or callback(nil) when missing (no
--- prompt then), callback(nil, err) on a real failure
function M.get(namespace, name, callback)
  check(namespace, name)
  if not store.read_item("items", namespace, name) then
    return later(callback, nil, nil)
  end
  with_key(function(ok, err)
    if not ok then
      return callback(nil, err)
    end
    local content = store.read_item("items", namespace, name)
    if not content then
      return callback(nil, nil)
    end
    local plaintext, item = store.open_item(S.dek, namespace, name, content)
    if not plaintext then
      return callback(nil, decrypt_error(namespace, name))
    end
    if item.kind == "secret" then
      return callback(plaintext, nil)
    end
    local decoded, value = pcall(vim.json.decode, plaintext, { luanil = { object = true, array = true } })
    if item.kind ~= "config" or not decoded then
      return callback(nil, decrypt_error(namespace, name))
    end
    callback(value, nil)
  end)
end

local function seal_and_write(kind, namespace, name, plaintext, callback)
  with_key(function(ok, err)
    if not ok then
      return callback(nil, err)
    end
    local written, write_err = pcall(function()
      store.write_item(kind, namespace, name, store.seal_item(S.dek, S.gen, kind, namespace, name, plaintext))
    end)
    callback(written or nil, not written and write_err or nil)
  end)
end

--- Store a string (a secret) or a table (config, JSON-serializable). callback(true) or
--- callback(nil, err)
function M.set(namespace, name, value, callback)
  check(namespace, name)
  callback = callback or function() end
  local kind, plaintext = "secret", value
  if type(value) == "table" then
    local ok, encoded = pcall(vim.json.encode, value)
    if not ok then
      error("locksmith.set: the value cannot be encoded as JSON: " .. tostring(encoded), 2)
    end
    kind, plaintext = "config", encoded
  elseif type(value) ~= "string" then
    error("locksmith.set: a string (secret) or a table (config) expected, got " .. type(value), 2)
  end
  seal_and_write(kind, namespace, name, plaintext, callback)
end

--- Delete a secret or config (no key needed). callback(true)
function M.delete(namespace, name, callback)
  check(namespace, name)
  store.delete_item("items", namespace, name)
  if callback then
    later(callback, true, nil)
  end
end

--- Names of the secrets and config of `namespace`, sorted (no key needed)
function M.list(namespace)
  store.check_name("namespace", namespace)
  return store.list("items", namespace)
end

--- Namespaces with secrets or config, sorted
function M.namespaces()
  return store.namespaces("items")
end

--- Disposable encrypted values of `namespace`: never re-encrypted, deleted when the data key
--- is rotated or by clear()
function M.cache(namespace)
  store.check_name("namespace", namespace)
  local cache = {}

  --- callback(value), nil when missing, undecryptable, or locked and the password declined
  function cache.load(name, callback)
    store.check_name("name", name)
    if not store.read_item("cache", namespace, name) then
      return later(callback, nil)
    end
    with_key(function(ok)
      local content = ok and store.read_item("cache", namespace, name)
      if not content then
        return callback(nil)
      end
      local plaintext, item = store.open_item(S.dek, namespace, name, content)
      local decoded, value = false, nil
      if plaintext and item.kind == "cache" then
        decoded, value = pcall(vim.json.decode, plaintext, { luanil = { object = true, array = true } })
      end
      if not decoded then
        store.delete_item("cache", namespace, name)
        return callback(nil)
      end
      callback(value)
    end)
  end

  --- callback(true) or callback(nil, err)
  function cache.save(name, value, callback)
    store.check_name("name", name)
    callback = callback or function() end
    local ok, encoded = pcall(vim.json.encode, value)
    if not ok then
      error("locksmith cache.save: the value cannot be encoded as JSON: " .. tostring(encoded), 2)
    end
    seal_and_write("cache", namespace, name, encoded, callback)
  end

  function cache.clear()
    store.clear_cache(namespace)
  end

  return cache
end

--- Re-encrypt every secret and config with a new data key (a new generation), then switch the
--- header to it; the caches are deleted. Nothing changes when an item cannot be decrypted
local function rotate(dek, header, password)
  return store.with_lock(function()
    local fresh = store.read_header()
    if not fresh or fresh.id ~= header.id or fresh.dek_generation ~= header.dek_generation then
      error("locksmith: the store changed meanwhile (another Neovim?): nothing done", 0)
    end
    local items = {}
    for _, namespace in ipairs(store.namespaces("items")) do
      for _, name in ipairs(store.list("items", namespace)) do
        local plaintext, item = store.open_item(dek, namespace, name, store.read_item("items", namespace, name) or "")
        if not plaintext then
          error(decrypt_error(namespace, name) .. ": nothing changed", 0)
        end
        table.insert(items, { namespace = namespace, name = name, kind = item.kind, plaintext = plaintext })
      end
    end
    local gen = fresh.dek_generation + 1
    local new_dek = crypto().random_into(crypto().key(), crypto().KEY_SIZE)
    local staged, err = pcall(function()
      for _, item in ipairs(items) do
        local content = store.seal_item(new_dek, gen, item.kind, item.namespace, item.name, item.plaintext)
        store.stage_item(item.namespace, item.name, content, gen)
      end
      fresh.dek_generation = gen
      store.set_kdf(fresh, config.kdf)
      local kek, kdf_err = store.derive_kek(password, fresh, config.backend)
      if not kek then
        error(kdf_err, 0)
      end
      store.wrap_dek(kek, new_dek, fresh)
      crypto().wipe(kek)
    end)
    if not staged then
      store.discard_staged()
      crypto().wipe(new_dek)
      error(err, 0)
    end
    store.write_header(fresh) -- the commit
    store.commit_staged(gen)
    store.clear_all_caches()
    crypto().wipe(dek)
    return new_dek, fresh, #items
  end)
end

--- Change the store's password: the current one, then the new one twice (and
--- set_password_check() when there is one). Only store.json changes: the items are not touched,
--- and other Neovims keep working. opts.rotate_data_key also replaces the data key, which
--- re-encrypts every secret and config and deletes the caches. callback(true) or (nil, err)
function M.change_password(callback, opts)
  callback = callback or function() end
  opts = opts or {}
  flow(function(done)
    local function finish(ok, err)
      done()
      call(callback, ok or nil, err)
    end
    local header, err = store.read_header()
    if not header then
      return finish(false, err or "there is no store yet: unlock it to create it")
    end
    local backend, backend_err = crypto().argon2_backend(config.backend)
    if not backend then
      return finish(false, backend_err)
    end
    ask("Current password: ", "password", function(old)
      if not old then
        return finish(false, "cancelled")
      end
      local dek, kdf_err = open_dek(header, old)
      if not dek then
        return finish(false, kdf_err or "wrong password: nothing changed")
      end
      ask_new("New password: ", function(password, new_err)
        if not password then
          crypto().wipe(dek)
          return finish(false, new_err .. ": nothing changed")
        end
        local was_unlocked = current()
        local ok, new_dek, fresh, count
        if opts.rotate_data_key then
          ok, new_dek, fresh, count = pcall(rotate, dek, header, password)
        else
          ok, fresh = pcall(rewrap, dek, header, password)
          new_dek = ok and dek or fresh
        end
        if not ok then
          crypto().wipe(dek)
          return finish(false, tostring(new_dek))
        end
        adopt(new_dek, fresh)
        if opts.rotate_data_key then
          notify(("password changed, new data key: %d items re-encrypted, caches deleted"):format(count))
        else
          notify("password changed")
        end
        if not was_unlocked then
          unlocked_with(password)
        end
        finish(true, nil)
      end)
    end)
  end)
end

--- Delete the store and everything in it, after a confirmation listing what is lost.
--- callback(true) or callback(nil, err)
function M.reset(callback)
  callback = callback or function() end
  flow(function(done)
    confirm_reset(function(ok, err)
      done()
      call(callback, ok or nil, err)
    end)
  end)
end

return M
