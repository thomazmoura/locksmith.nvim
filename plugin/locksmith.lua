-- :Locksmith, and nothing else at startup: the module (and libcrypto) load on first use
if vim.g.loaded_locksmith then
  return
end
vim.g.loaded_locksmith = true

vim.api.nvim_create_user_command("Locksmith", function(info)
  require("locksmith.command").command(info)
end, {
  nargs = "*",
  bang = true,
  desc = "locksmith: encrypted store of secrets, config and caches",
  complete = function(arglead, line)
    return require("locksmith.command").complete(arglead, line)
  end,
})
