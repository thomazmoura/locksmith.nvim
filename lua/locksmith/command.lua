-- :Locksmith and bin/locksmith: the same subcommands. Values are never arguments (those go to
-- the command history and ShaDa): `set` asks them hidden, reads stdin (the command line) or
-- opens a scratch buffer (config). Secrets are shown masked unless asked for with `get!`, and
-- then in a floating window (or on stdout), never in a message.
local M = {}

local ls = require("locksmith")
local prompt = require("locksmith.prompt")
local store = require("locksmith.store")

M.USAGE = [[
Usage: locksmith status                      the store: where, locked or not, KDF parameters
       locksmith list [NAMESPACE]            names of the secrets and config (no password)
       locksmith get[!] NAMESPACE/NAME       a secret, masked unless with ! (or --reveal)
       locksmith set NAMESPACE/NAME [--config]
                                             store a secret, typed (hidden) or piped on stdin;
                                             --config: a JSON table (a config item)
       locksmith delete NAMESPACE/NAME       delete a secret or config
       locksmith unlock | lock               enter the password / forget the key
       locksmith passwd [--rotate-data-key]  change the password (and the data key)
       locksmith reset                       delete the store and everything in it
In Neovim: :Locksmith with the same subcommands.]]

M.SUBCOMMANDS = { "status", "list", "get", "set", "delete", "unlock", "lock", "passwd", "reset" }

--- `ghp_…3f9a`: 4 characters at each end of a long secret, nothing of a short one
function M.mask(secret)
  if #secret >= 16 then
    return secret:sub(1, 4) .. "…" .. secret:sub(-4)
  end
  return ("… (%d characters)"):format(#secret)
end

local function target(arg)
  local namespace, name = (arg or ""):match("^([^/]+)/([^/]+)$")
  if namespace and store.valid_name(namespace) and store.valid_name(name) then
    return namespace, name
  end
end

--- JSON with one key per line, keys sorted: readable and editable, decoded back identically.
--- Here, not through jq: a config value never goes to another process
function M.pretty(value, indent)
  indent = indent or ""
  if type(value) ~= "table" then
    return vim.json.encode(value)
  end
  local inner = indent .. "  "
  local parts = {}
  if vim.islist(value) and next(value) ~= nil then
    for _, item in ipairs(value) do
      table.insert(parts, inner .. M.pretty(item, inner))
    end
    return "[\n" .. table.concat(parts, ",\n") .. "\n" .. indent .. "]"
  end
  local keys = vim.tbl_keys(value)
  if #keys == 0 then
    return "{}"
  end
  table.sort(keys, function(a, b)
    return tostring(a) < tostring(b)
  end)
  for _, key in ipairs(keys) do
    table.insert(parts, ("%s%s: %s"):format(inner, vim.json.encode(tostring(key)), M.pretty(value[key], inner)))
  end
  return "{\n" .. table.concat(parts, ",\n") .. "\n" .. indent .. "}"
end

local pretty = M.pretty

--- Run a subcommand. `ui` is how it talks to the user:
---   info(message), reveal(title, text) (a secret: a float, or stdout),
---   read_value(label, callback(value)), edit_config(title, text, callback(text)),
---   always_reveal (stdout is not a terminal: `get` prints the value itself)
--- done(err, output) once finished (err = M.USAGE for a usage error)
---@param args string[]
function M.run(args, ui, done)
  local flags, words = {}, {}
  for _, arg in ipairs(args) do
    if arg:match("^%-%-") or arg == "-r" then
      flags[arg] = true
    else
      table.insert(words, arg)
    end
  end
  local cmd = words[1]
  local bang = false
  if cmd and cmd:sub(-1) == "!" then
    cmd, bang = cmd:sub(1, -2), true
  end
  bang = bang or ui.bang or flags["--reveal"] or flags["-r"]

  local needs_target = cmd == "get" or cmd == "set" or cmd == "delete"
  local namespace, name = target(words[2])
  if needs_target and not namespace then
    return done("expected NAMESPACE/NAME (letters, digits, '.', '_', '-'), e.g. workhorse/pat")
  end
  local label = needs_target and (namespace .. "/" .. name) or nil

  if cmd == "status" then
    local status = ls.status()
    local lines = {
      ("store:    %s (%s)"):format(status.path, status.exists and "exists" or "not created yet"),
      ("caches:   %s"):format(status.cache_path),
      ("unlocked: %s"):format(status.unlocked and "yes" or "no"),
      ("Argon2id: %s"):format(status.backend or "no backend available"),
    }
    if status.kdf then
      table.insert(lines, ("KDF:      t = %d, m = %d MiB, p = %d"):format(status.kdf.t, status.kdf.m / 1024, status.kdf.p))
      table.insert(lines, ("data key: generation %d"):format(status.dek_generation))
      table.insert(lines, ("created:  %s, password changed %s"):format(status.created, status.changed))
    end
    if status.error then
      table.insert(lines, "error:    " .. status.error)
    end
    return done(nil, table.concat(lines, "\n"))
  elseif cmd == "list" then
    local lines = {}
    if words[2] then
      if not store.valid_name(words[2]) then
        return done("invalid namespace " .. words[2])
      end
      lines = ls.list(words[2])
    else
      for _, ns in ipairs(ls.namespaces()) do
        for _, item in ipairs(ls.list(ns)) do
          table.insert(lines, ns .. "/" .. item)
        end
      end
      local caches = store.namespaces("cache")
      if #caches > 0 then
        table.insert(lines, "(caches: " .. table.concat(caches, ", ") .. ")")
      end
    end
    return done(nil, #lines > 0 and table.concat(lines, "\n") or "(empty)")
  elseif cmd == "get" then
    return ls.get(namespace, name, function(value, err)
      if err then
        return done(err)
      end
      if value == nil then
        return done(label .. " is not in the store")
      end
      if type(value) == "table" then
        ui.reveal(label, pretty(value))
        return done(nil, nil)
      end
      if bang or ui.always_reveal then
        ui.reveal(label, value)
        return done(nil, nil)
      end
      done(nil, ("%s = %s (:Locksmith get! %s to see it)"):format(label, M.mask(value), label))
    end)
  elseif cmd == "set" then
    -- The password first: a value typed before a wrong one would be wasted
    return ls.unlock(function(ok, err)
      if not ok then
        return done(err)
      end
      ls.get(namespace, name, function(current, get_err)
        if get_err then
          return done(get_err)
        end
        local function stored(set_ok, set_err)
          done(set_err, set_ok and ("stored " .. label) or nil)
        end
        if flags["--config"] or type(current) == "table" then
          return ui.edit_config(label, type(current) == "table" and pretty(current) or "{\n}", function(text)
            if not text then
              return done("cancelled: nothing stored")
            end
            local decoded, value = pcall(vim.json.decode, text, { luanil = { object = true, array = true } })
            if not decoded or type(value) ~= "table" then
              return done("not a JSON object or array: nothing stored")
            end
            ls.set(namespace, name, value, stored)
          end)
        end
        ui.read_value(("Value of %s: "):format(label), function(value)
          if not value or value == "" then
            return done("no value entered: nothing stored")
          end
          ls.set(namespace, name, value, stored)
        end)
      end)
    end)
  elseif cmd == "delete" then
    if not vim.list_contains(ls.list(namespace), name) then
      return done(label .. " is not in the store")
    end
    return ls.delete(namespace, name, function()
      done(nil, "deleted " .. label)
    end)
  elseif cmd == "unlock" then
    return ls.unlock(function(ok, err)
      done(err, ok and "unlocked" or nil)
    end)
  elseif cmd == "lock" then
    ls.lock()
    return done(nil, "locked: the data key was zeroed")
  elseif cmd == "passwd" then
    return ls.change_password(function(ok, err)
      done(err, ok and "password changed" or nil)
    end, { rotate_data_key = flags["--rotate-data-key"] })
  elseif cmd == "reset" then
    return ls.reset(function(ok, err)
      done(err, ok and "the store was deleted" or nil)
    end)
  end
  done(M.USAGE)
end

-- Neovim -----------------------------------------------------------------------------------

--- A scratch buffer that leaves no trace: no file, no swap file, no undo file, not listed
--- (so not in ShaDa), wiped when hidden
local function scratch(buftype, name, lines)
  local buf = vim.api.nvim_create_buf(false, true)
  vim.bo[buf].buftype = buftype
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
  vim.bo[buf].buflisted = false
  if name then
    vim.api.nvim_buf_set_name(buf, name)
  end
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  return buf
end

local function float(buf, title, enter)
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  local width = 30
  for _, line in ipairs(lines) do
    width = math.max(width, vim.fn.strdisplaywidth(line) + 2)
  end
  width = math.min(width, math.max(vim.o.columns - 4, 20))
  local height = math.min(math.max(#lines, 1), math.max(vim.o.lines - 6, 3))
  return vim.api.nvim_open_win(buf, enter, {
    relative = "editor",
    width = width,
    height = height,
    row = math.floor((vim.o.lines - height) / 2) - 1,
    col = math.floor((vim.o.columns - width) / 2),
    style = "minimal",
    border = "rounded",
    title = " " .. title .. " ",
    title_pos = "center",
  })
end

--- How :Locksmith talks to the user
local function nvim_ui(bang)
  return {
    bang = bang,
    reveal = function(title, text)
      local buf = scratch("nofile", nil, vim.split(text, "\n", { plain = true }))
      vim.bo[buf].modifiable = false
      local win = float(buf, title .. " (q to close)", true)
      local function close()
        if vim.api.nvim_win_is_valid(win) then
          vim.api.nvim_win_close(win, true)
        end
      end
      for _, key in ipairs({ "q", "<Esc>" }) do
        vim.keymap.set("n", key, close, { buffer = buf, nowait = true })
      end
      vim.api.nvim_create_autocmd("WinLeave", { buffer = buf, once = true, callback = close })
    end,
    read_value = function(label, callback)
      prompt.ask(label, { kind = "password" }, callback)
    end,
    edit_config = function(title, text, callback)
      local buf = scratch("acwrite", "locksmith://" .. title, vim.split(text, "\n", { plain = true }))
      vim.bo[buf].filetype = "json"
      local answered = false
      vim.api.nvim_create_autocmd("BufWriteCmd", {
        buffer = buf,
        callback = function()
          answered = true
          callback(table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n"))
          vim.bo[buf].modified = false
          vim.schedule(function()
            if vim.api.nvim_buf_is_valid(buf) then
              vim.api.nvim_buf_delete(buf, { force = true })
            end
          end)
        end,
      })
      vim.api.nvim_create_autocmd("BufWipeout", {
        buffer = buf,
        once = true,
        callback = function()
          if not answered then
            callback(nil)
          end
        end,
      })
      float(buf, title .. " (:w to store, :q to cancel)", true)
    end,
  }
end

--- :Locksmith
function M.command(info)
  local ui = nvim_ui(info.bang)
  M.run(info.fargs, ui, function(err, output)
    if err == M.USAGE then
      prompt.notify(err)
    elseif err then
      prompt.notify(err, vim.log.levels.ERROR)
    elseif output then
      prompt.notify(output)
    end
  end)
end

function M.complete(arglead, line)
  local words = vim.split(vim.trim(line), "%s+")
  local count = #words + (line:match("%s$") and 1 or 0)
  if count <= 2 then
    return vim.tbl_filter(function(sub)
      return vim.startswith(sub, arglead)
    end, vim.list_extend(vim.list_slice(M.SUBCOMMANDS), { "get!" }))
  end
  local sub = words[2]:gsub("!$", "")
  if count == 3 and (sub == "get" or sub == "set" or sub == "delete") then
    local names = {}
    for _, ns in ipairs(ls.namespaces()) do
      for _, item in ipairs(ls.list(ns)) do
        table.insert(names, ns .. "/" .. item)
      end
    end
    return vim.tbl_filter(function(name)
      return vim.startswith(name, arglead)
    end, names)
  end
  if count == 3 and sub == "list" then
    return ls.namespaces()
  end
  if sub == "set" then
    return { "--config" }
  elseif sub == "passwd" then
    return { "--rotate-data-key" }
  end
  return {}
end

-- Command line -----------------------------------------------------------------------------

--- Entry point of bin/locksmith (nvim -l): run a subcommand and exit
---@param args string[] the `arg` of nvim -l
function M.main(args)
  local function finish(message, code)
    local out = code == 0 and io.stdout or io.stderr
    if message then
      out:write(message, "\n")
    end
    out:flush()
    os.exit(code)
  end
  -- Non-dumpable before anything is typed: no ptrace, no /proc/<pid>/mem, no core dump
  if not require("locksmith.crypto").harden() then
    finish("locksmith: could not make this process non-dumpable", 1)
  end
  if not args[1] or args[1] == "help" or args[1] == "--help" or args[1] == "-h" then
    finish(M.USAGE, args[1] and 0 or 2)
  end

  local piped = vim.uv.guess_handle(0) ~= "tty"
  local function stdin()
    -- `pass show x | locksmith set ns/x`: a single trailing newline dropped
    return ((io.read("*a") or ""):gsub("\r?\n$", ""))
  end
  local ui = {
    always_reveal = vim.uv.guess_handle(1) ~= "tty",
    reveal = function(_, text)
      io.stdout:write(text, "\n")
      io.stdout:flush()
    end,
    read_value = function(label, callback)
      if piped then
        return callback(stdin())
      end
      prompt.ask(label, { kind = "password" }, callback)
    end,
    edit_config = function(_, _, callback)
      if piped then
        return callback(stdin())
      end
      prompt.ask("JSON: ", { kind = "text" }, callback)
    end,
  }
  local result = nil
  M.run(args, ui, function(err, output)
    result = { err, output }
  end)
  vim.wait(24 * 3600 * 1000, function()
    return result ~= nil
  end, 20)
  if result[1] == M.USAGE then
    finish(M.USAGE, 2)
  elseif result[1] then
    finish("locksmith: " .. result[1], 1)
  end
  finish(result[2], 0)
end

return M
