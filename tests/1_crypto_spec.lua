local crypto = require("locksmith.crypto")
local ffi = require("ffi")

local function hex(s)
  return (s:gsub("..", function(h)
    return string.char(tonumber(h, 16))
  end))
end

local function tohex(s)
  return (s:gsub(".", function(c)
    return ("%02x"):format(c:byte())
  end))
end

local function key_from(bytes)
  local key = crypto.key()
  ffi.copy(key, bytes, #bytes)
  return key
end

T.test("libcrypto is available", function()
  T.ok(crypto.available())
end)

-- RFC 9106 section 5.3
T.test("Argon2id matches the RFC 9106 test vector on every available backend", function()
  local found = 0
  for _, backend in ipairs(crypto.BACKEND_ORDER) do
    if crypto.argon2_backend(backend) then
      found = found + 1
      local out = ffi.new("uint8_t[32]")
      T.ok(crypto.argon2id(out, 32, ("\1"):rep(32), ("\2"):rep(16), {
        t = 3,
        m = 32,
        p = 4,
        backend = backend,
        secret = ("\3"):rep(8),
        ad = ("\4"):rep(12),
      }))
      T.eq(tohex(ffi.string(out, 32)), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", backend)
    end
  end
  T.ok(found > 0, "no Argon2id backend")
end)

T.test("both Argon2id backends compute the same key", function()
  if not (crypto.argon2_backend("openssl") and crypto.argon2_backend("libargon2")) then
    return
  end
  local a, b = crypto.key(), crypto.key()
  T.ok(crypto.argon2id(a, 32, "correct horse", "0123456789abcdef", { t = 1, m = 8192, p = 2, backend = "openssl" }))
  T.ok(crypto.argon2id(b, 32, "correct horse", "0123456789abcdef", { t = 1, m = 8192, p = 2, backend = "libargon2" }))
  T.eq(ffi.string(a, 32), ffi.string(b, 32))
end)

T.test("an unknown or missing backend is refused, never replaced", function()
  local ok, err = crypto.argon2id(crypto.key(), 32, "x", ("s"):rep(16), { t = 1, m = 64, p = 1, backend = "pbkdf2" })
  T.eq(ok, false)
  T.ok(err:find("unknown"))
end)

-- The GCM specification (McGrew and Viega), test case 16: AES-256, 96-bit IV, with AAD
T.test("AES-256-GCM matches the GCM test case 16", function()
  local key = key_from(hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"))
  local plaintext = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    .. "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
  local aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  local iv, ct, tag = crypto.seal(key, plaintext, aad, hex("cafebabefacedbaddecaf888"))
  T.eq(tohex(iv), "cafebabefacedbaddecaf888")
  T.eq(tohex(ct), "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    .. "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
  T.eq(tohex(tag), "76fc6ece0f4e1768cddf8853bb2d551b")
  T.eq(crypto.open(key, iv, ct, tag, aad), plaintext)
end)

T.test("seal and open round trip, with a fresh nonce each time", function()
  local key = crypto.random_into(crypto.key(), 32)
  local iv1, ct1, tag1 = crypto.seal(key, "hunter2", "aad")
  local iv2, ct2 = crypto.seal(key, "hunter2", "aad")
  T.ok(iv1 ~= iv2 and ct1 ~= ct2, "nonce reused")
  T.eq(#iv1, 12)
  T.eq(crypto.open(key, iv1, ct1, tag1, "aad"), "hunter2")
  local iv, ct, tag = crypto.seal(key, "", "aad")
  T.eq(crypto.open(key, iv, ct, tag, "aad"), "")
end)

T.test("a flipped bit in the ciphertext, tag, nonce, AAD or key fails to open", function()
  local key = crypto.random_into(crypto.key(), 32)
  local iv, ct, tag = crypto.seal(key, "a secret value", "locksmith:1|secret|ns|name|1")
  local aad = "locksmith:1|secret|ns|name|1"
  local function flip(s, i)
    return s:sub(1, i - 1) .. string.char(bit.bxor(s:byte(i), 1)) .. s:sub(i + 1)
  end
  T.eq(crypto.open(key, iv, flip(ct, 3), tag, aad), nil, "ciphertext")
  T.eq(crypto.open(key, iv, ct, flip(tag, 16), aad), nil, "tag")
  T.eq(crypto.open(key, flip(iv, 1), ct, tag, aad), nil, "nonce")
  T.eq(crypto.open(key, iv, ct, tag, flip(aad, #aad)), nil, "aad")
  T.eq(crypto.open(key, iv, ct, tag:sub(1, 15), aad), nil, "short tag")
  local other = crypto.key()
  ffi.copy(other, key, 32)
  other[31] = bit.bxor(other[31], 1)
  T.eq(crypto.open(other, iv, ct, tag, aad), nil, "key")
  T.eq(crypto.open(key, iv, ct, tag, aad), "a secret value")
end)

T.test("open_into decrypts a key into a buffer, wipe zeroes it", function()
  local kek = crypto.random_into(crypto.key(), 32)
  local dek = crypto.random_into(crypto.key(), 32)
  local iv, ct, tag = crypto.seal(kek, dek, "header", nil, 32)
  local out = crypto.key()
  T.eq(crypto.open_into(kek, iv, ct, tag, "header", out), 32)
  T.eq(ffi.string(out, 32), ffi.string(dek, 32))
  crypto.wipe(out)
  T.ok(crypto.is_zero(out))
  T.eq(crypto.open_into(kek, iv, ct, tag, "other", out), nil)
  T.ok(crypto.is_zero(out))
end)
