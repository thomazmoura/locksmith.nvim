-- Entry point of bin/locksmith (run by nvim --clean -l): the module of this checkout
local root = vim.fn.fnamemodify(arg[0], ":p:h:h")
vim.opt.rtp:prepend(root)
package.path = ("%s/lua/?.lua;%s/lua/?/init.lua;"):format(root, root) .. package.path
require("locksmith.command").main(arg)
