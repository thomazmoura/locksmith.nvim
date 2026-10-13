-- Questions to the user: passwords (hidden), choices and confirmations. With a UI through
-- inputsecret(), vim.ui.select() and input(); headless (nvim -l, a daemon started from a
-- terminal) on /dev/tty, with echo off for passwords; or through the function given to
-- set_prompt(). Nothing typed goes to a history, a register or a message.
local M = {}

--- set_prompt(): fn(message, callback, opts), opts = { kind = "password"|"text"|"confirm"|
--- "choice", choices = { ... } }; callback(answer), the index or text of a choice
M.custom = nil

function M.headless()
  return #vim.api.nvim_list_uis() == 0
end

function M.notify(message, level)
  if M.headless() then
    io.stderr:write("locksmith: " .. message .. "\n")
    return
  end
  vim.notify("locksmith: " .. message, level or vim.log.levels.INFO)
end

--- A line from the terminal, without echo for a password. nil without a terminal
local function tty_read(message, hidden)
  local tty = io.open("/dev/tty", "r+")
  if not tty then
    return nil
  end
  -- Echo off before the prompt shows: what is typed as soon as it does is not echoed
  if hidden then
    os.execute("stty -echo < /dev/tty 2> /dev/null")
  end
  tty:write(message)
  tty:flush()
  local ok, line = pcall(tty.read, tty, "*l")
  if hidden then
    os.execute("stty echo < /dev/tty 2> /dev/null")
    tty:write("\n")
  end
  tty:close()
  return ok and line or nil
end

local function with_choices(message, choices)
  local lines = { message }
  for i, choice in ipairs(choices) do
    table.insert(lines, ("  %d. %s"):format(i, choice))
  end
  table.insert(lines, "Choice (empty to cancel): ")
  return table.concat(lines, "\n")
end

--- The answer, normalized: a non-empty string, a choice's index, or nil (cancelled)
local function normalize(answer, opts)
  if opts.kind == "choice" then
    local index = tonumber(answer)
    return index and opts.choices[index] and index or nil
  end
  if type(answer) ~= "string" or answer == "" then
    return nil
  end
  return answer
end

local function ask_ui(message, opts, callback)
  if opts.kind == "choice" then
    return vim.ui.select(opts.choices, { prompt = message }, function(_, index)
      callback(index)
    end)
  end
  local ok, answer
  if opts.kind == "password" then
    -- Not recorded in the input history (unlike input())
    ok, answer = pcall(vim.fn.inputsecret, message)
  else
    ok, answer = pcall(vim.fn.input, { prompt = message, cancelreturn = "" })
  end
  vim.cmd("redraw")
  callback(ok and answer or nil)
end

local function ask_tty(message, opts, callback)
  if opts.kind == "choice" then
    return callback(tty_read(with_choices(message, opts.choices), false))
  end
  callback(tty_read(message, opts.kind == "password"))
end

--- Ask a question: callback(answer) on the main loop, nil when cancelled or left empty
---@param message string
---@param opts table|nil { kind = "password" (default)|"text"|"confirm"|"choice", choices }
---@param callback function
function M.ask(message, opts, callback)
  opts = vim.tbl_extend("keep", opts or {}, { kind = "password" })
  local answered = false
  local function done(answer)
    if answered then
      return
    end
    answered = true
    vim.schedule(function()
      callback(normalize(answer, opts))
    end)
  end
  vim.schedule(function()
    if M.custom then
      local text = opts.kind == "choice" and with_choices(message, opts.choices) or message
      local ok, err = pcall(M.custom, text, done, opts)
      if not ok then
        M.notify("prompt failed: " .. tostring(err), vim.log.levels.ERROR)
        done(nil)
      end
    elseif M.headless() then
      ask_tty(message, opts, done)
    else
      ask_ui(message, opts, done)
    end
  end)
end

return M
