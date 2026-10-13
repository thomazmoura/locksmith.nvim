# locksmith.nvim

An encrypted store for Neovim plugins: **secrets** (tokens, PATs), **config** (JSON tables) and
**caches** (large, disposable), each under a namespace (one per plugin). It is unlocked once
per Neovim with a password that is **never written anywhere, not even encrypted**: not to disk,
another process's argv, environment or stdin, `vim.g`, a history, a register, ShaDa or a log.

That password is meant to be your domain password (machine login, Kerberos, Exchange): one
prompt for every plugin, and a store that follows the password when AD rotates it. Every
decision below assumes that a cracked store means a compromised domain account.

Requires Neovim with LuaJIT (0.10+), libcrypto (OpenSSL 3) and an Argon2id implementation:
**libargon2** (`libargon2-1` on Debian/Ubuntu, `argon2` on Arch) or **OpenSSL ≥ 3.2**. Without
either, locksmith refuses to create or open the store: it never falls back to a weaker KDF.

## Install

```lua
-- lazy.nvim, as a dependency of the plugin using it
{ "thomazmoura/workhorse.nvim", dependencies = { "thomazmoura/locksmith.nvim" } }
```

Nothing heavy loads at startup: `plugin/locksmith.lua` only defines `:Locksmith`, and
libcrypto is loaded on first use.

## What it protects against, and what not

It protects against:

- **the disk or a backup being read** (a lost laptop without full-disk encryption, `~/.local`
  synced or backed up somewhere): every value is encrypted, and guessing the password offline
  costs one Argon2id derivation (256 MiB of memory) per guess;
- **other users of the machine**: directories are mode 0700, files 0600 (from their creation,
  before any byte is written);
- **processes running as you reading Neovim's memory**: once the store is unlocked, Neovim is
  made non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`): no ptrace, no `/proc/<pid>/mem`, no core
  dumps. This also stops gdb from attaching to that Neovim: `setup({ harden = false })` turns
  it off;
- **tampering with or swapping sealed files**: AES-GCM authenticates every file, and an item's
  identity (kind, namespace, name, key generation) is part of its AAD, so a file renamed,
  moved to another namespace or turned from a cache into a secret fails to open. The header's
  KDF parameters, salt and key generation are the AAD of the wrapped key: they cannot be
  downgraded without breaking the unwrap.

It does **not** protect against:

- **code running as you that changes your Neovim config or plugins, or logs the terminal**: it
  can simply wait for you to type the password;
- **root**;
- **swap without encryption**: the data key may be paged out. Use encrypted swap (or none).

Also, **names are visible**: `items/workhorse/pat.json` tells anyone who can list the
directory that workhorse keeps a `pat`. Listing needs no password. That metadata leak is
accepted.

## Design

```
password ──Argon2id(salt, t, m, p)──▶ KEK (key encryption key, memory only, zeroed after use)
                                         │ AES-256-GCM wrap
random 256-bit DEK (data encryption key) ◀┘   stored only wrapped, in store.json
DEK ──AES-256-GCM, random 96-bit nonce, AAD = item identity──▶ every item and cache file
```

- **Envelope encryption.** Changing the password re-wraps one 32-byte key in one file, an
  atomic rename: the items are never touched, a half-done re-key cannot happen, and other
  running Neovims keep working, because their data key did not change.
- **Argon2id**, version 1.3, through libargon2 (`argon2_ctx`) or OpenSSL ≥ 3.2
  (`EVP_KDF "ARGON2ID"`). Both compute the same function (both pass the RFC 9106 test vector),
  so a store created with one opens with the other. libargon2 is preferred: it is faster.
- **AES-256-GCM** through libcrypto, a random 96-bit nonce for every write.
- **Keys** live in `uint8_t[32]` FFI buffers handed to libcrypto as they are: they never become
  Lua strings. The key encryption key is zeroed right after the unwrap, the data key by
  `lock()`. The password is a Lua string, which cannot be wiped: the key is derived straight
  away, every reference to the password dropped, and the garbage collector run.
- Everything happens in the Neovim process, through LuaJIT FFI: no `openssl` subprocess.

### KDF parameters and timing

Defaults: `t = 3` passes, `m = 262144` KiB (256 MiB), `p = 4` lanes, 16-byte random salt.
They are stored in the header, so each store keeps its own; `setup({ kdf = ... })` sets the
parameters used when a store is created or its password changed.

Measured on a 12-core laptop, median of 3:

| Parameters               | libargon2 | OpenSSL 3.5 |
| ------------------------ | --------- | ----------- |
| t = 3, m = 256 MiB, p = 4 (default) | 618 ms | 944 ms |
| t = 2, m = 256 MiB, p = 4 | 455 ms   | 776 ms      |
| t = 3, m = 128 MiB, p = 4 | 301 ms   | 462 ms      |

The derivation runs on the main loop: Neovim is busy for that time, once per unlock.

### On disk

```
$XDG_DATA_HOME/locksmith/                          0700   (data: not wiped by cache cleaners)
  store.json                                       0600   header
  items/<namespace>/<name>.json                    0600   sealed secret or config
$XDG_CACHE_HOME/locksmith/<namespace>/<name>.json  0600   sealed cache
```

- `store.json`: `{ "format": "locksmith:1", "id", "kdf": { "alg": "argon2id", "t", "m",
  "p", "salt" }, "dek_generation", "wrapped_dek": { "iv", "ct", "tag" }, "created",
  "changed" }`, byte fields in base64. `id` is random per store: a session notices that
  another Neovim reset the store.
- A sealed file: `{ "format": "locksmith:1", "kind", "gen", "iv", "ct", "tag" }`. The
  plaintext is the string itself for a secret, `vim.json.encode(value)` for config and caches.
  Its AAD: `locksmith:1|<kind>|<namespace>|<name>|<gen>`.
- Namespaces and names match `^[%w._-]+$` (and are not only dots).
- Every write goes to a temporary file in the same directory (mode 0600 from its creation),
  is fsynced and renamed over the target. `store.json` is only rewritten under a lock file
  (`store.json.lock`, created with `O_EXCL`; one older than 30 s is a crash's and is removed).

## Lua API

Calls that may need the key are asynchronous (they may prompt): `callback(value, err)`, run on
the main loop.

```lua
local ls = require("locksmith")
ls.setup({ prompt = nil, harden = true, kdf = { t = 3, m = 262144, p = 4 } }) -- optional

-- secrets and config
ls.get(ns, name, cb)              -- cb(value) / cb(nil) when missing (no prompt) / cb(nil, err)
ls.set(ns, name, value, cb)       -- string → secret, table → config; cb(true) / cb(nil, err)
ls.delete(ns, name, cb)
ls.list(ns)                       -- names, synchronous (no key needed)
ls.namespaces()                   -- namespaces with items

-- caches (disposable)
local cache = ls.cache(ns)
cache.load(name, cb)              -- nil when missing, undecryptable or locked-and-declined
cache.save(name, value, cb)       -- any JSON-serializable value
cache.clear()

-- session
ls.unlock(cb)                     -- prompts (once, shared); creates the store on first use
ls.lock()                         -- zeroes the data key
ls.status()                       -- { exists, unlocked, kdf, dek_generation, path, backend, ... }
ls.change_password(cb, opts)      -- old password, new one twice; opts.rotate_data_key
ls.reset(cb)                      -- deletes everything, after a confirmation
ls.on_unlock(fn)                  -- fn(password) once, after the next successful unlock
ls.set_prompt(fn)                 -- fn(message, cb, opts) replaces inputsecret / the tty
ls.set_password_check(fn)         -- fn(password, cb(ok, err)) vets a new password
```

Every consumer shares one session: the state lives in the module, and `require` returns the
same copy to every plugin. Concurrent calls wait on the same prompt. After the user declines
the prompt (empty, `<C-c>`), calls fail without asking again until `ls.unlock()` (or
`:Locksmith unlock`), so a plugin refreshing in the background does not nag.

A custom prompt gets `opts.kind`: `"password"` (hide it), `"text"`, `"confirm"` (answer with
the text typed), or `"choice"` with `opts.choices` (answer with the index; `message` lists
them numbered too).

### Handing the password to a consumer

A consumer that needs the same password elsewhere (paperboy, for Exchange) registers
`on_unlock(fn)`: `fn(password)` is called **once**, right after the next successful unlock,
and only with a password that opened the store. That is the only way the password leaves the
module, and locksmith keeps no copy. When the store is already unlocked, the password is gone:
`fn` is not called, `on_unlock` returns `false` (with a message saying so), and the consumer
asks the user itself.

## Changing the password

`:Locksmith passwd` (or `ls.change_password`): the current password, then the new one twice.
Only `store.json` changes. With `set_password_check`, the new password is also vetted before
the store is re-keyed (paperboy tries it against Exchange).

When AD rotated the password first, the next unlock fails, and locksmith offers:

1. **Retry**, for a typo. The password is never sent anywhere, so nothing counts toward an AD
   lockout.
2. **My password changed**: type the previous one, which opens the store, and the store is
   re-wrapped with the one just typed. That one is confirmed by `set_password_check` when a
   consumer set one, typed again otherwise: a typo never becomes the store's password.
3. **I don't remember the previous one**: everything is deleted, after a confirmation listing
   what is lost, and a new store is created.

`:Locksmith passwd --rotate-data-key` also replaces the data key, for when the old one may have
leaked: every secret and config is re-encrypted (staged next to the items, committed by the
`store.json` rename, then renamed in; an interrupted rotation is finished at the next unlock),
the caches are deleted, and the key generation goes up. Other Neovims notice the new generation
and ask the password again instead of writing with a stale key.

## Commands

```
:Locksmith status                 where the store is, locked or not, KDF parameters
:Locksmith list [ns]              names (no password needed)
:Locksmith get ns/name            a secret, masked: ghp_…3f9a
:Locksmith get! ns/name           the secret itself, in a floating window
:Locksmith set ns/name            asks the value with inputsecret()
:Locksmith set ns/name --config   edits a config table as JSON in a scratch buffer (:w stores)
:Locksmith delete ns/name
:Locksmith unlock | lock
:Locksmith passwd [--rotate-data-key]
:Locksmith reset
```

Values are never arguments: those go to the command history and ShaDa. Secrets never go to
`:echo` or `vim.notify` (which keep them in `:messages`): the masked form does, the value
itself only goes to a floating window. The scratch buffers have no file, swap file or undo
file, are unlisted (so not in ShaDa), and are wiped when closed.

### Command line

`bin/locksmith` runs `nvim --headless --clean -l bin/locksmith.lua` with the same
subcommands, for terminals and scripts. It is non-dumpable from its start. The password is read
on `/dev/tty`, echo off. `set` reads the value on stdin when stdin is not a terminal, and `get`
prints the value itself when stdout is not a terminal:

```sh
pass show azure/pat | locksmith set workhorse/pat
export AZURE_DEVOPS_PAT=$(locksmith get workhorse/pat)
```

## Headless scripts

A script started with `nvim --clean -l` (a daemon, a tmux status command) does not see lazy's
runtimepath. It works headless as well: the prompt and the wrong-password menu go to
`/dev/tty`. Find the module like this, and fail clearly otherwise:

```lua
local function find_locksmith()
  for _, dir in ipairs({
    vim.fn.expand("~/code/locksmith.nvim"),
    vim.fn.stdpath("data") .. "/lazy/locksmith.nvim",
  }) do
    if vim.uv.fs_stat(dir .. "/lua/locksmith/init.lua") then
      vim.opt.rtp:prepend(dir)
      return require("locksmith")
    end
  end
  io.stderr:write("locksmith.nvim not found: install it (lazy.nvim) or clone it to ~/code\n")
  os.exit(1)
end
```

## Tests

```sh
nvim --headless -l tests/run.lua          # all of them
nvim --headless -l tests/run.lua session  # the files whose name contains "session"
```

They use small Argon2id parameters (`t = 1`, `m = 8 MiB`), temporary `$XDG_DATA_HOME` and
`$XDG_CACHE_HOME`, and scripted prompts. The command tests drive `bin/locksmith` in a
pseudo-terminal and `:Locksmith` in an embedded Neovim, typing as a user would.

## Out of scope

A Secret Service / keyring backend, importing from the `vault.lua` these plugins used before
(each consumer asks its few secrets again), syncing between machines, a Neovim without LuaJIT.
