-- Cryptographic primitives of locksmith, in this process through LuaJIT FFI: AES-256-GCM,
-- RAND_bytes and Argon2id from libcrypto (OpenSSL >= 3.2) or libargon2, prctl from libc.
-- Nothing secret ever goes to another process.
--
-- Keys are `uint8_t[32]` buffers (M.key()), handed to libcrypto as they are and zeroed by
-- M.wipe(): they never become Lua strings, which cannot be wiped. Loaded on first use only.
local M = {}

local ffi = require("ffi")

local EVP_CTRL_GCM_SET_IVLEN = 0x9
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11
local PR_GET_DUMPABLE = 3
local PR_SET_DUMPABLE = 4
local OSSL_PARAM_UNSIGNED_INTEGER = 2
local OSSL_PARAM_OCTET_STRING = 5
local ARGON2_ID = 2
local ARGON2_VERSION_13 = 0x13

M.KEY_SIZE = 32
M.IV_SIZE = 12
M.TAG_SIZE = 16

-- One at a time, each in a pcall: a declaration another plugin made already in this process
-- (vault.lua declares the same functions, with these same signatures) fails alone
local DECLARATIONS = {
  "const void *EVP_aes_256_gcm(void);",
  "void *EVP_CIPHER_CTX_new(void);",
  "void EVP_CIPHER_CTX_free(void *);",
  "int EVP_CIPHER_CTX_ctrl(void *, int, int, void *);",
  "int EVP_EncryptInit_ex(void *, const void *, void *, const unsigned char *, const unsigned char *);",
  "int EVP_EncryptUpdate(void *, unsigned char *, int *, const unsigned char *, int);",
  "int EVP_EncryptFinal_ex(void *, unsigned char *, int *);",
  "int EVP_DecryptInit_ex(void *, const void *, void *, const unsigned char *, const unsigned char *);",
  "int EVP_DecryptUpdate(void *, unsigned char *, int *, const unsigned char *, int);",
  "int EVP_DecryptFinal_ex(void *, unsigned char *, int *);",
  "int RAND_bytes(unsigned char *, int);",
  "int prctl(int, unsigned long, unsigned long, unsigned long, unsigned long);",
  "void *EVP_KDF_fetch(void *, const char *, const char *);",
  "void EVP_KDF_free(void *);",
  "void *EVP_KDF_CTX_new(void *);",
  "void EVP_KDF_CTX_free(void *);",
  "int OSSL_set_max_threads(void *, uint64_t);",
  -- Private names: the layout of OSSL_PARAM and argon2_context, filled by hand
  [[typedef struct {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
  } locksmith_ossl_param;]],
  "int EVP_KDF_derive(void *, unsigned char *, size_t, const locksmith_ossl_param *);",
  [[typedef struct {
    uint8_t *out; uint32_t outlen;
    uint8_t *pwd; uint32_t pwdlen;
    uint8_t *salt; uint32_t saltlen;
    uint8_t *secret; uint32_t secretlen;
    uint8_t *ad; uint32_t adlen;
    uint32_t t_cost; uint32_t m_cost; uint32_t lanes; uint32_t threads;
    uint32_t version;
    void *allocate_cbk; void *free_cbk;
    uint32_t flags;
  } locksmith_argon2_context;]],
  "int argon2_ctx(locksmith_argon2_context *, int);",
}

local libcrypto, libargon2 = nil, nil

local function declare()
  for _, declaration in ipairs(DECLARATIONS) do
    pcall(ffi.cdef, declaration)
  end
end

--- libcrypto, nil when it cannot be loaded
local function crypto()
  if libcrypto == nil then
    declare()
    libcrypto = false
    for _, name in ipairs({ "crypto", "libcrypto.so.3" }) do
      local ok, loaded = pcall(ffi.load, name)
      if ok then
        libcrypto = loaded
        break
      end
    end
  end
  return libcrypto or nil
end

--- libargon2, nil when it cannot be loaded
local function argon2()
  if libargon2 == nil then
    declare()
    libargon2 = false
    for _, name in ipairs({ "argon2", "libargon2.so.1" }) do
      local ok, loaded = pcall(ffi.load, name)
      if ok then
        libargon2 = loaded
        break
      end
    end
  end
  return libargon2 or nil
end

--- Is libcrypto there? (AES-GCM and the random numbers need it)
---@return boolean ok
---@return string|nil err
function M.available()
  if not crypto() then
    return false, "libcrypto (OpenSSL 3) not found: install OpenSSL"
  end
  return true, nil
end

-- Buffers ----------------------------------------------------------------------------------

--- A zeroed key buffer
---@return ffi.cdata* uint8_t[32]
function M.key()
  return ffi.new("uint8_t[?]", M.KEY_SIZE)
end

--- Zero a buffer (a key, a password copy)
function M.wipe(buffer, size)
  if buffer ~= nil then
    ffi.fill(buffer, size or M.KEY_SIZE, 0)
  end
end

--- Is every byte of `buffer` zero?
function M.is_zero(buffer, size)
  for i = 0, (size or M.KEY_SIZE) - 1 do
    if buffer[i] ~= 0 then
      return false
    end
  end
  return true
end

--- Fill `buffer` with `size` random bytes
function M.random_into(buffer, size)
  if crypto().RAND_bytes(buffer, size) ~= 1 then
    error("locksmith: RAND_bytes failed")
  end
  return buffer
end

---@return string bytes
function M.random(size)
  local buffer = ffi.new("uint8_t[?]", size)
  M.random_into(buffer, size)
  return ffi.string(buffer, size)
end

-- AES-256-GCM ------------------------------------------------------------------------------

--- Encrypt `size` bytes at `plaintext` (a string or a buffer) under `key` (a key buffer)
---@param iv string|nil 12 bytes; random when nil. Tests only: a nonce is never chosen
---@return string iv
---@return string ciphertext
---@return string tag
function M.seal(key, plaintext, aad, iv, size)
  local C = crypto()
  size = size or #plaintext
  iv = iv or M.random(M.IV_SIZE)
  local out = ffi.new("uint8_t[?]", size + 16)
  local tag = ffi.new("uint8_t[16]")
  local length, final = ffi.new("int[1]"), ffi.new("int[1]")
  local ctx = C.EVP_CIPHER_CTX_new()
  local ok = ctx ~= nil
    and C.EVP_EncryptInit_ex(ctx, C.EVP_aes_256_gcm(), nil, nil, nil) == 1
    and C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, #iv, nil) == 1
    and C.EVP_EncryptInit_ex(ctx, nil, nil, key, iv) == 1
    and C.EVP_EncryptUpdate(ctx, nil, length, aad, #aad) == 1
    and C.EVP_EncryptUpdate(ctx, out, length, plaintext, size) == 1
    and C.EVP_EncryptFinal_ex(ctx, out + length[0], final) == 1
    and C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1
  local total = length[0] + final[0]
  C.EVP_CIPHER_CTX_free(ctx)
  if not ok then
    error("locksmith: AES-GCM encryption failed")
  end
  local ciphertext = ffi.string(out, total)
  M.wipe(out, size + 16)
  return iv, ciphertext, ffi.string(tag, 16)
end

--- Decrypt into `out` (a buffer of at least #ciphertext bytes): the plaintext never becomes
--- a Lua string
---@return integer|nil size of the plaintext: nil when the key is wrong or anything was altered
function M.open_into(key, iv, ciphertext, tag, aad, out)
  if type(iv) ~= "string" or type(tag) ~= "string" or #tag ~= M.TAG_SIZE or #iv == 0 then
    return nil
  end
  local C = crypto()
  local length, final = ffi.new("int[1]"), ffi.new("int[1]")
  local tag_buffer = ffi.new("uint8_t[16]")
  ffi.copy(tag_buffer, tag, 16)
  local ctx = C.EVP_CIPHER_CTX_new()
  local ok = ctx ~= nil
    and C.EVP_DecryptInit_ex(ctx, C.EVP_aes_256_gcm(), nil, nil, nil) == 1
    and C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, #iv, nil) == 1
    and C.EVP_DecryptInit_ex(ctx, nil, nil, key, iv) == 1
    and C.EVP_DecryptUpdate(ctx, nil, length, aad, #aad) == 1
    and C.EVP_DecryptUpdate(ctx, out, length, ciphertext, #ciphertext) == 1
    and C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buffer) == 1
    and C.EVP_DecryptFinal_ex(ctx, out + length[0], final) == 1
  local total = length[0] + final[0]
  C.EVP_CIPHER_CTX_free(ctx)
  if not ok then
    M.wipe(out, #ciphertext)
    return nil
  end
  return total
end

--- Decrypt to a string (items: not keys)
---@return string|nil plaintext: nil when the key is wrong or anything was altered
function M.open(key, iv, ciphertext, tag, aad)
  local size = math.max(#ciphertext, 1)
  local out = ffi.new("uint8_t[?]", size)
  local total = M.open_into(key, iv, ciphertext, tag, aad, out)
  if not total then
    return nil
  end
  local plaintext = ffi.string(out, total)
  M.wipe(out, size)
  return plaintext
end

-- Argon2id ---------------------------------------------------------------------------------

local function threads_for(lanes)
  local C = crypto()
  -- OpenSSL computes the lanes one after the other unless it may start threads (3.2+)
  local ok, set = pcall(function()
    return C.OSSL_set_max_threads(nil, lanes)
  end)
  return (ok and set == 1) and lanes or 1
end

local BACKENDS = {}

BACKENDS.openssl = {
  available = function()
    local C = crypto()
    if not C then
      return false
    end
    local ok, kdf = pcall(function()
      return C.EVP_KDF_fetch(nil, "ARGON2ID", nil)
    end)
    if not ok or kdf == nil then
      return false
    end
    C.EVP_KDF_free(kdf)
    return true
  end,
  derive = function(out, outlen, password, salt, t, m, p, secret, ad)
    local C = crypto()
    local kdf = C.EVP_KDF_fetch(nil, "ARGON2ID", nil)
    local ctx = kdf ~= nil and C.EVP_KDF_CTX_new(kdf) or nil
    if kdf ~= nil then
      C.EVP_KDF_free(kdf)
    end
    if ctx == nil then
      return false
    end
    local pwd = ffi.new("uint8_t[?]", math.max(#password, 1))
    ffi.copy(pwd, password, #password)
    local numbers = ffi.new("uint32_t[4]", t, m, p, threads_for(p))
    local kept = { pwd, numbers }
    local function bytes(value)
      local buffer = ffi.new("uint8_t[?]", math.max(#value, 1))
      ffi.copy(buffer, value, #value)
      kept[#kept + 1] = buffer
      return buffer
    end
    local params = ffi.new("locksmith_ossl_param[9]") -- 8 at most, and the end marker
    local n = 0
    local function add(key, kind, data, size)
      kept[#kept + 1] = key
      params[n].key, params[n].data_type, params[n].data, params[n].data_size = key, kind, data, size
      params[n].return_size = ffi.cast("size_t", -1)
      n = n + 1
    end
    add("pass", OSSL_PARAM_OCTET_STRING, pwd, #password)
    add("salt", OSSL_PARAM_OCTET_STRING, bytes(salt), #salt)
    add("iter", OSSL_PARAM_UNSIGNED_INTEGER, numbers + 0, 4)
    add("memcost", OSSL_PARAM_UNSIGNED_INTEGER, numbers + 1, 4)
    add("lanes", OSSL_PARAM_UNSIGNED_INTEGER, numbers + 2, 4)
    add("threads", OSSL_PARAM_UNSIGNED_INTEGER, numbers + 3, 4)
    if secret then
      add("secret", OSSL_PARAM_OCTET_STRING, bytes(secret), #secret)
    end
    if ad then
      add("ad", OSSL_PARAM_OCTET_STRING, bytes(ad), #ad)
    end
    -- params[n] stays zeroed: the end marker
    local ok = C.EVP_KDF_derive(ctx, out, outlen, params) == 1
    C.EVP_KDF_CTX_free(ctx)
    M.wipe(pwd, math.max(#password, 1))
    local _ = kept
    return ok
  end,
}

BACKENDS.libargon2 = {
  available = function()
    return argon2() ~= nil
  end,
  derive = function(out, outlen, password, salt, t, m, p, secret, ad)
    local A = argon2()
    local pwd = ffi.new("uint8_t[?]", math.max(#password, 1))
    ffi.copy(pwd, password, #password)
    local salt_buffer = ffi.new("uint8_t[?]", #salt)
    ffi.copy(salt_buffer, salt, #salt)
    local context = ffi.new("locksmith_argon2_context")
    context.out, context.outlen = out, outlen
    context.pwd, context.pwdlen = pwd, #password
    context.salt, context.saltlen = salt_buffer, #salt
    local kept = {}
    if secret then
      kept.secret = ffi.new("uint8_t[?]", #secret)
      ffi.copy(kept.secret, secret, #secret)
      context.secret, context.secretlen = kept.secret, #secret
    end
    if ad then
      kept.ad = ffi.new("uint8_t[?]", #ad)
      ffi.copy(kept.ad, ad, #ad)
      context.ad, context.adlen = kept.ad, #ad
    end
    context.t_cost, context.m_cost, context.lanes, context.threads = t, m, p, p
    context.version = ARGON2_VERSION_13
    local ok = A.argon2_ctx(context, ARGON2_ID) == 0
    M.wipe(pwd, math.max(#password, 1))
    return ok
  end,
}

-- libargon2 first: the same function, but faster (about 620 ms against 940 ms for the
-- default parameters on a 12-core laptop)
M.BACKEND_ORDER = { "libargon2", "openssl" }

local INSTALL_HINT = "no Argon2id implementation found: install OpenSSL >= 3.2 or libargon2 "
  .. "(Debian/Ubuntu: libargon2-1, Arch: argon2, Fedora: libargon2)"

--- Name of the Argon2id backend to use: `preferred` when given and available, else the first
--- available one. Never a weaker KDF instead
---@param preferred string|nil "openssl" or "libargon2"
---@return string|nil name
---@return string|nil err
function M.argon2_backend(preferred)
  if preferred then
    if not BACKENDS[preferred] then
      return nil, ("unknown Argon2id backend %q"):format(preferred)
    end
    if not BACKENDS[preferred].available() then
      return nil, ("the %s Argon2id backend is not available"):format(preferred)
    end
    return preferred, nil
  end
  for _, name in ipairs(M.BACKEND_ORDER) do
    if BACKENDS[name].available() then
      return name, nil
    end
  end
  return nil, INSTALL_HINT
end

--- Argon2id (version 1.3) of `password` into `out` (a buffer of `outlen` bytes)
---@param params table { t, m (KiB), p, backend = name|nil, secret = string|nil, ad = string|nil }
---@return boolean ok
---@return string|nil err
function M.argon2id(out, outlen, password, salt, params)
  local name, err = M.argon2_backend(params.backend)
  if not name then
    return false, err
  end
  if not BACKENDS[name].derive(out, outlen, password, salt, params.t, params.m, params.p, params.secret, params.ad) then
    M.wipe(out, outlen)
    return false, ("Argon2id failed (%s backend)"):format(name)
  end
  return true, nil
end

-- Process hardening ------------------------------------------------------------------------

--- Make this process non-dumpable: other processes of the same user can neither ptrace it
--- nor read /proc/<pid>/mem, and there are no core dumps
---@return boolean ok
function M.harden()
  declare()
  return ffi.C.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
end

---@return boolean dumpable
function M.dumpable()
  declare()
  return ffi.C.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1
end

return M
