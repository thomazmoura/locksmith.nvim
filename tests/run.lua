-- Tests of locksmith: nvim --headless -l tests/run.lua [filter]
-- Runs every tests/*_spec.lua (only those whose name contains `filter` when given). Each
-- test gets fresh $XDG_DATA_HOME and $XDG_CACHE_HOME and a fresh copy of the module, with
-- small Argon2id parameters.
local root = vim.fn.fnamemodify(arg[0], ":p:h:h")
vim.opt.rtp:prepend(root)
package.path = ("%s/lua/?.lua;%s/lua/?/init.lua;%s/tests/?.lua;"):format(root, root, root) .. package.path

local T = { root = root, passed = 0, failed = {}, current = nil }
_G.T = T

T.KDF = { t = 1, m = 8192, p = 2 }

local function show(value)
  return type(value) == "string" and ("%q"):format(value) or vim.inspect(value)
end

function T.eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error(("%sexpected %s, got %s"):format(message and (message .. ": ") or "", show(expected), show(actual)), 2)
  end
end

function T.ok(value, message)
  if not value then
    error(message or "expected a true value", 2)
  end
  return value
end

--- Run fn(done) and wait until done(...) is called: its arguments are returned
function T.await(fn, timeout)
  local result = nil
  fn(function(...)
    result = { n = select("#", ...), ... }
  end)
  if not vim.wait(timeout or 20000, function()
    return result ~= nil
  end, 5) then
    error("timed out", 2)
  end
  return unpack(result, 1, result.n)
end

--- Let scheduled callbacks run
function T.settle(ms)
  vim.wait(ms or 50, function()
    return false
  end, 5)
end

function T.read(path)
  local handle = io.open(path, "rb")
  if not handle then
    return nil
  end
  local content = handle:read("*a")
  handle:close()
  return content
end

function T.write(path, content)
  local handle = assert(io.open(path, "wb"))
  handle:write(content)
  handle:close()
end

function T.mode(path)
  local stat = vim.uv.fs_stat(path)
  return stat and ("%o"):format(bit.band(stat.mode, tonumber("777", 8))) or nil
end

--- Fresh, empty $XDG_DATA_HOME and $XDG_CACHE_HOME
function T.dirs()
  T.home = vim.fn.tempname()
  vim.fn.mkdir(T.home, "p")
  vim.env.XDG_DATA_HOME = T.home .. "/data"
  vim.env.XDG_CACHE_HOME = T.home .. "/cache"
end

--- Fresh directories and a fresh locksmith (its session state is the module's): returns it
function T.fresh(opts)
  T.dirs()
  return T.instance(opts)
end

--- Another copy of locksmith over the same directories: a second Neovim's session
function T.instance(opts)
  for name in pairs(package.loaded) do
    if name == "locksmith" or (name:match("^locksmith%.") and name ~= "locksmith.crypto") then
      package.loaded[name] = nil
    end
  end
  -- Messages are collected instead of printed
  T.messages = {}
  require("locksmith.prompt").notify = function(message)
    table.insert(T.messages, message)
  end
  local ls = require("locksmith")
  ls.setup(vim.tbl_deep_extend("force", { harden = false, kdf = T.KDF }, opts or {}))
  return ls
end

--- A scripted prompt: answers are taken in order (a function answer is called with the
--- message and opts). Returns it, with .calls = { { message, opts } }
function T.script(answers, delay)
  local prompt = { calls = {}, answers = answers }
  prompt.fn = function(message, callback, opts)
    table.insert(prompt.calls, { message = message, kind = opts and opts.kind })
    local answer = table.remove(prompt.answers, 1)
    if type(answer) == "function" then
      answer = answer(message, opts)
    end
    if delay then
      vim.defer_fn(function()
        callback(answer)
      end, delay)
    else
      callback(answer)
    end
  end
  return prompt
end

function T.test(name, fn)
  T.current = name
  local ok, err = xpcall(fn, debug.traceback)
  if ok then
    T.passed = T.passed + 1
    io.stdout:write("  ok   " .. name .. "\n")
  else
    table.insert(T.failed, name)
    io.stdout:write("  FAIL " .. name .. "\n" .. tostring(err):gsub("\n", "\n       ") .. "\n")
  end
  -- A test leaving the store unlocked does not leak into the next one
  local loaded = package.loaded["locksmith"]
  if loaded then
    pcall(loaded.lock)
  end
end

local filter = arg[1]
local files = vim.fn.glob(root .. "/tests/*_spec.lua", false, true)
table.sort(files)
for _, file in ipairs(files) do
  if not filter or file:find(filter, 1, true) then
    io.stdout:write(vim.fn.fnamemodify(file, ":t") .. "\n")
    local ok, err = xpcall(dofile, debug.traceback, file)
    if not ok then
      table.insert(T.failed, file)
      io.stdout:write("  FAIL loading: " .. tostring(err) .. "\n")
    end
  end
end

io.stdout:write(("\n%d passed, %d failed\n"):format(T.passed, #T.failed))
io.stdout:flush()
os.exit(#T.failed == 0 and 0 or 1)
