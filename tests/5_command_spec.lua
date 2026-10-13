local SECRET = "super-secret-value-1234"
local BIN = T.root .. "/bin/locksmith"

--- A store created in this process with password "pw": returns the module
local function with_store()
  local ls = T.fresh()
  ls.set_prompt(T.script({ "pw", "pw" }).fn)
  T.eq(T.await(ls.unlock), true)
  ls.lock()
  return ls
end

--- Run `cmd` (a shell command line) in a pseudo-terminal: its /dev/tty is ours. `answers`
--- maps a pattern of its output to the line typed once it shows up. Returns code, output
local function in_pty(cmd, answers)
  local output, code = "", nil
  local pending = vim.deepcopy(answers or {})
  local job = vim.fn.jobstart({ "sh", "-c", cmd }, {
    pty = true,
    env = { XDG_DATA_HOME = vim.env.XDG_DATA_HOME, XDG_CACHE_HOME = vim.env.XDG_CACHE_HOME },
    on_stdout = function(_, data)
      output = output .. table.concat(data, "\n")
    end,
    on_exit = function(_, exit_code)
      code = exit_code
    end,
  })
  T.ok(job > 0, "jobstart failed")
  local typed = 0
  T.ok(vim.wait(20000, function()
    local next_answer = pending[1]
    if next_answer then
      local _, count = output:gsub(next_answer[1], "")
      if count > typed then
        typed = typed + 1
        vim.fn.chansend(job, next_answer[2] .. "\n")
        table.remove(pending, 1)
      end
    end
    return code ~= nil
  end, 10), "timed out: " .. output)
  return code, output
end

T.test("bin/locksmith set reads the value on stdin, the password on the terminal", function()
  local ls = with_store()
  local code, output = in_pty(("printf '%s\\n' | %s set ns/piped"):format(SECRET, BIN), { { "password:", "pw" } })
  T.eq(code, 0, output)
  T.ok(output:find("stored ns/piped"), output)
  T.ok(not output:find(SECRET, 1, true), "value echoed")
  T.ok(not output:find("pw\r?\n"), "password echoed")
  ls.set_prompt(T.script({ "pw" }).fn)
  T.eq(T.await(function(done)
    ls.get("ns", "piped", done)
  end), SECRET)
end)

T.test("bin/locksmith get masks on a terminal, prints the value into a pipe", function()
  local ls = with_store()
  ls.set_prompt(T.script({ "pw" }).fn)
  T.await(function(done)
    ls.set("ns", "pat", SECRET, done)
  end)
  local code, output = in_pty(BIN .. " get ns/pat", { { "password:", "pw" } })
  T.eq(code, 0, output)
  T.ok(output:find("supe…1234", 1, true), output)
  T.ok(not output:find(SECRET, 1, true), "value shown")
  local file = T.home .. "/out"
  code, output = in_pty(("%s get ns/pat > %s"):format(BIN, file), { { "password:", "pw" } })
  T.eq(code, 0, output)
  T.eq(T.read(file), SECRET .. "\n")
  code, output = in_pty(BIN .. " get! ns/pat", { { "password:", "pw" } })
  T.ok(output:find(SECRET, 1, true), output)
end)

T.test("bin/locksmith set --config reads JSON on stdin", function()
  local ls = with_store()
  local code, output = in_pty(("echo '{\"url\": \"https://x\", \"n\": [1, 2]}' | %s set ns/conf --config"):format(BIN), {
    { "password:", "pw" },
  })
  T.eq(code, 0, output)
  ls.set_prompt(T.script({ "pw" }).fn)
  T.eq(T.await(function(done)
    ls.get("ns", "conf", done)
  end), { url = "https://x", n = { 1, 2 } })
end)

T.test("bin/locksmith reports errors with a non-zero exit code", function()
  with_store()
  local code, output = in_pty(BIN .. " get ns/missing", { { "password:", "pw" } })
  T.eq(code, 1)
  T.ok(output:find("not in the store"), output)
  code = in_pty(BIN .. " frobnicate")
  T.eq(code, 2)
end)

-- :Locksmith in a child Neovim, typed into as a user would -------------------------------

local function child()
  local nvim = vim.fn.jobstart({
    vim.v.progpath,
    "--embed",
    "--headless",
    "--clean",
    "--cmd",
    "set rtp^=" .. T.root,
  }, { rpc = true, env = { XDG_DATA_HOME = vim.env.XDG_DATA_HOME, XDG_CACHE_HOME = vim.env.XDG_CACHE_HOME } })
  local function lua(code, ...)
    return vim.rpcrequest(nvim, "nvim_exec_lua", code, { ... })
  end
  -- A UI as far as locksmith can tell: inputsecret() and messages, not the terminal
  lua([[
    vim.api.nvim_list_uis = function() return { {} } end
    require("locksmith").setup({ harden = false, kdf = ... })
  ]], T.KDF)
  --- The prompt of an open input() / inputsecret(), nothing typed into it yet
  local function prompt()
    if vim.rpcrequest(nvim, "nvim_get_mode").mode ~= "c" then
      return nil
    end
    return lua("return vim.fn.getcmdline() == '' and vim.fn.getcmdprompt() or nil")
  end
  local function wait(fn, what)
    T.ok(vim.wait(10000, fn, 10), "timed out waiting for " .. what)
  end
  --- Type `keys`, then wait for the prompt matching `next_prompt`, or for normal mode
  local function type_keys(keys, next_prompt)
    vim.rpcrequest(nvim, "nvim_input", keys)
    wait(function()
      if next_prompt then
        local shown = prompt()
        return shown ~= nil and shown ~= vim.NIL and shown:find(next_prompt) ~= nil
      end
      return vim.rpcrequest(nvim, "nvim_get_mode").mode == "n"
    end, next_prompt or ("normal mode after " .. keys))
  end
  return { id = nvim, lua = lua, type = type_keys, wait = wait }
end

T.test(":Locksmith set and get leave no value in messages, histories or registers", function()
  T.dirs()
  local nvim = child()
  -- The store is created on the way: the password twice, then the value
  nvim.type(":Locksmith set ns/x\r", "New password")
  nvim.type("pw\r", "again")
  nvim.type("pw\r", "Value of ns/x")
  nvim.type(SECRET .. "\r")
  nvim.wait(function()
    return vim.deep_equal(nvim.lua("return require('locksmith').list('ns')"), { "x" })
  end, "the item")

  nvim.type(":Locksmith get ns/x\r")
  nvim.wait(function()
    return nvim.lua("return vim.fn.execute('messages')"):find("supe…1234", 1, true) ~= nil
  end, "the masked value")

  nvim.type(":Locksmith get! ns/x\r")
  local shown = nvim.lua([[
    local win = vim.api.nvim_get_current_win()
    return { relative = vim.api.nvim_win_get_config(win).relative,
             lines = vim.api.nvim_buf_get_lines(0, 0, -1, false),
             buftype = vim.bo.buftype, swapfile = vim.bo.swapfile, listed = vim.bo.buflisted }
  ]])
  T.eq(shown.relative, "editor")
  T.eq(shown.lines, { SECRET })
  T.eq({ shown.buftype, shown.swapfile, shown.listed }, { "nofile", false, false })
  nvim.type("q")
  T.eq(nvim.lua("return vim.api.nvim_win_get_config(0).relative"), "")

  local traces = nvim.lua([[
    local out = { messages = vim.fn.execute("messages"), errmsg = vim.v.errmsg }
    for _, history in ipairs({ ":", "@", "/", "=", ">" }) do
      for i = 1, vim.fn.histnr(history) do
        out["hist" .. history .. i] = vim.fn.histget(history, i)
      end
    end
    for _, reg in ipairs(vim.split('"0123456789abcdefghijklmnopqrstuvwxyz-:./', "")) do
      out["reg" .. reg] = vim.fn.getreg(reg)
    end
    return out
  ]])
  for where, text in pairs(traces) do
    T.ok(not text:find(SECRET, 1, true), "the value is in " .. where)
    T.ok(not text:find("pw", 1, true) or where:match("^hist:") or where:match("^reg:"), "the password is in " .. where)
  end
  T.eq(traces["hist:1"], "Locksmith set ns/x")
  vim.fn.jobstop(nvim.id)
end)

T.test(":Locksmith set --config edits JSON in a scratch buffer", function()
  T.dirs()
  local nvim = child()
  nvim.type(":Locksmith unlock\r", "New password")
  nvim.type("pw\r", "again")
  nvim.type("pw\r")
  nvim.type(":Locksmith set ns/conf --config\r")
  local buffer = nvim.lua([[
    return { name = vim.api.nvim_buf_get_name(0), buftype = vim.bo.buftype, swapfile = vim.bo.swapfile,
             undofile = vim.bo.undofile, bufhidden = vim.bo.bufhidden, listed = vim.bo.buflisted }
  ]])
  T.eq(buffer, {
    name = "locksmith://ns/conf",
    buftype = "acwrite",
    swapfile = false,
    undofile = false,
    bufhidden = "wipe",
    listed = false,
  })
  nvim.lua([[vim.api.nvim_buf_set_lines(0, 0, -1, false, { '{ "token_url": "https://t", "retries": 3 }' })]])
  nvim.type(":w\r")
  nvim.wait(function()
    return vim.deep_equal(nvim.lua("return require('locksmith').list('ns')"), { "conf" })
  end, "the config item")
  T.eq(nvim.lua("return vim.api.nvim_buf_get_name(0)"), "")
  local value = nvim.lua([[
    local result
    require("locksmith").get("ns", "conf", function(v) result = v end)
    vim.wait(5000, function() return result ~= nil end)
    return result
  ]])
  T.eq(value, { token_url = "https://t", retries = 3 })
  vim.fn.jobstop(nvim.id)
end)

T.test("masking", function()
  local command = require("locksmith.command")
  T.eq(command.mask("ghp_abcdefghijklmnop3f9a"), "ghp_…3f9a")
  T.eq(command.mask("short"), "… (5 characters)")
end)

T.test("pretty JSON decodes back to the same value", function()
  local command = require("locksmith.command")
  local value = { b = { 1, 2, { c = "x" } }, a = vim.empty_dict(), d = {}, e = true, f = "q\"uote" }
  local text = command.pretty(value)
  T.ok(text:find('\n  "a": {}', 1, true), text)
  T.eq(vim.json.decode(text), vim.json.decode(vim.json.encode(value)))
end)
