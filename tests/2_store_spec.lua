local crypto = require("locksmith.crypto")
local ffi = require("ffi")

local function setup()
  T.dirs()
  package.loaded["locksmith.store"] = nil
  local store = require("locksmith.store")
  local header = store.new_header(T.KDF)
  local kek = assert(store.derive_kek("password", header))
  local dek = crypto.random_into(crypto.key(), 32)
  store.wrap_dek(kek, dek, header)
  store.with_lock(function()
    store.write_header(header)
  end)
  return store, dek
end

T.test("the header round trips and unwraps with the right password only", function()
  local store, dek = setup()
  local header = assert(store.read_header())
  local kek = assert(store.derive_kek("password", header))
  local out = crypto.key()
  T.ok(store.unwrap_dek(kek, header, out))
  T.eq(ffi.string(out, 32), ffi.string(dek, 32))
  local wrong = assert(store.derive_kek("Password", header))
  T.eq(store.unwrap_dek(wrong, header, crypto.key()), false)
end)

T.test("directories are 0700, files 0600", function()
  local store, dek = setup()
  store.write_item("secret", "ns", "pat", store.seal_item(dek, 1, "secret", "ns", "pat", "x"))
  store.write_item("cache", "ns", "contacts", store.seal_item(dek, 1, "cache", "ns", "contacts", "{}"))
  T.eq(T.mode(store.data_dir()), "700")
  T.eq(T.mode(store.data_dir() .. "/items"), "700")
  T.eq(T.mode(store.data_dir() .. "/items/ns"), "700")
  T.eq(T.mode(store.cache_dir()), "700")
  T.eq(T.mode(store.cache_dir() .. "/ns"), "700")
  T.eq(T.mode(store.header_path()), "600")
  T.eq(T.mode(store.item_path("items", "ns", "pat")), "600")
  T.eq(T.mode(store.item_path("cache", "ns", "contacts")), "600")
end)

T.test("a crash between write and rename leaves the old file intact", function()
  local store, dek = setup()
  store.write_item("secret", "ns", "pat", store.seal_item(dek, 1, "secret", "ns", "pat", "old"))
  local before = T.read(store.item_path("items", "ns", "pat"))
  store.hooks.before_rename = function()
    error("crash")
  end
  T.eq(pcall(store.write_item, "secret", "ns", "pat", store.seal_item(dek, 1, "secret", "ns", "pat", "new")), false)
  store.hooks.before_rename = nil
  T.eq(T.read(store.item_path("items", "ns", "pat")), before)
  T.eq(store.open_item(dek, "ns", "pat", before), "old")
  -- The temporary file left behind is not an item
  T.eq(#vim.fn.glob(store.data_dir() .. "/items/ns/.*.tmp", true, true), 1)
  T.eq(store.list("items", "ns"), { "pat" })
end)

T.test("a renamed or moved item fails to open (its identity is in the AAD)", function()
  local store, dek = setup()
  store.write_item("secret", "ns", "a", store.seal_item(dek, 1, "secret", "ns", "a", "value"))
  local content = T.read(store.item_path("items", "ns", "a"))
  T.eq(store.open_item(dek, "ns", "a", content), "value")
  vim.uv.fs_rename(store.item_path("items", "ns", "a"), store.item_path("items", "ns", "b"))
  T.eq(store.open_item(dek, "ns", "b", T.read(store.item_path("items", "ns", "b"))), nil)
  T.eq(store.open_item(dek, "other", "a", content), nil)
end)

T.test("changing an item's kind or generation fails to open", function()
  local store, dek = setup()
  local content = store.seal_item(dek, 1, "secret", "ns", "a", "value")
  T.eq(store.open_item(dek, "ns", "a", (content:gsub('"secret"', '"config"'))), nil)
  T.eq(store.open_item(dek, "ns", "a", (content:gsub('"gen":1', '"gen":2'))), nil)
end)

T.test("a header with altered KDF parameters, generation or salt fails to unwrap", function()
  local store = setup()
  local original = T.read(store.header_path())
  local function try(mutate)
    local header = vim.json.decode(original)
    mutate(header)
    T.write(store.header_path(), vim.json.encode(header))
    local read = assert(store.read_header())
    local kek = assert(store.derive_kek("password", read))
    return store.unwrap_dek(kek, read, crypto.key())
  end
  T.eq(try(function() end), true, "unaltered")
  T.eq(try(function(h)
    h.kdf.t = h.kdf.t + 1
  end), false, "t")
  T.eq(try(function(h)
    h.kdf.m = h.kdf.m * 2
  end), false, "m")
  -- Not an input of the KDF: only the AAD catches these
  T.eq(try(function(h)
    h.dek_generation = 2
  end), false, "generation")
  T.eq(try(function(h)
    h.id = vim.base64.encode(("x"):rep(16))
  end), false, "id")
end)

T.test("a header with absurd KDF parameters is refused before deriving anything", function()
  local store = setup()
  local header = vim.json.decode(T.read(store.header_path()))
  header.kdf.m = 1e12
  T.write(store.header_path(), vim.json.encode(header))
  local read, err = store.read_header()
  T.eq(read, nil)
  T.ok(err:find("invalid KDF parameter m"))
end)

T.test("the lock file excludes a second writer, a stale one is removed", function()
  local store = setup()
  local lock = store.header_path() .. ".lock"
  T.write(lock, "12345")
  store.LOCK_WAIT = 100
  local ok, err = pcall(store.with_lock, function() end)
  T.eq(ok, false)
  T.ok(tostring(err):find("held by another process"))
  local old = os.time() - 60
  vim.uv.fs_utime(lock, old, old)
  T.eq(store.with_lock(function()
    return "ran"
  end), "ran")
  T.eq(vim.uv.fs_stat(lock), nil)
end)

T.test("names are checked", function()
  local store = require("locksmith.store")
  for _, name in ipairs({ "pat", "cache-key", "a.b_c", ".hidden" }) do
    T.ok(store.valid_name(name), name)
  end
  for _, name in ipairs({ "", ".", "..", "a/b", "a b", "ç", ("x"):rep(200) }) do
    T.eq(store.valid_name(name), false, name)
  end
end)
