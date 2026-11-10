# FinishUP servers

By default FinishUP runs one service on your own computer, and your agents, the `finishup`
command and the terminal interface all use it. A **server** lets them use a different FinishUP
service instead: a **named local server** on this computer, with its own tasks, settings and
vault, **your own FinishUP server on another machine, over SSH**, or **a FinishUP server over
HTTPS**, on the web or on a port of this computer, that you reach with an API key.

Nothing changes until you add a server and choose to use it. Without one, FinishUP behaves exactly
as it always has.

This release connects to FinishUP servers on this computer (the everyday server and the named
local servers you add), to FinishUP servers on another machine over SSH, and to FinishUP servers
over HTTPS (on the web, or on a port of this computer). To let other computers use a FinishUP you
run, see [Serve this computer over HTTPS](#serve-this-computer-over-https).

## Add a server

```text
finishup server add lab --local
```

A name is up to 16 lowercase letters, digits and hyphens, starting with a letter or digit. `local`
is reserved: it always means the everyday FinishUP on this computer. FinishUP shows a server's
name where you manage servers yourself: the `finishup server` commands (`add`, `use`, `list`,
`status`, `test`, `connect`, `disconnect`, `set`, `login`, `logout` and `remove`) and `/server` in
the terminal interface.
Error codes, logs and receipts name a server only by a short id such as `t_1a2b3c4d`.

A named local server is a second FinishUP on this computer, with its own tasks, vault, privacy
policy and AI-powered review settings. It starts when something first needs it, like the everyday
one. It needs its own setup: choose it (below) and run `finishup setup`, exactly as for a first
installation.

## Add a server on another machine (SSH)

```text
finishup server add lab ssh://me@lab.example
finishup server add lab ssh://me@lab.example:2222 --remote-launcher /opt/finishup/bin/finishup
```

The address is `ssh://[user@]host[:port]`; the port is 22 unless you give one. Run the command in
your own terminal: OpenSSH may ask you a question there, and you confirm what the server may
receive by typing its name.

Before you add one, check:

- **The same FinishUP release on the server**, set up there as on any computer. FinishUP looks for
  it at `~/.local/bin/finishup`, `/opt/homebrew/bin/finishup`, `/usr/local/bin/finishup` and
  `/usr/bin/finishup` on the server; if it is somewhere else, give its full path with
  `--remote-launcher`. Unlocking its vault happens on the server only, never from this computer.
- **SSH key login to the account that runs FinishUP on the server.** FinishUP uses your own
  OpenSSH (`ssh` on this computer, with your SSH configuration, keys and agent) and never asks for
  or stores a password or key. A key protected by a passphrase must be loaded in your SSH agent
  first (`ssh-add`); password and one-time-code logins are not used.
- **The server's SSH service allows forwarding to a local socket** (OpenSSH's
  `AllowStreamLocalForwarding`, on by default). FinishUP reaches the server's own FinishUP through
  it.
- **The server's FinishUP keeps listening after you log out.** By default it listens in your login
  session's runtime folder, which the system removes at your last logout. Enable lingering for
  that account on the server (`loginctl enable-linger`), or run the server's FinishUP from its own
  folder and give that folder with `--remote-root`. `server add` warns you when this applies.

What `server add` does, in order:

1. It asks the server over SSH where its FinishUP listens and what it offers (it may start the
   server's FinishUP service to answer).
2. If this computer does not know the server's SSH host key yet, FinishUP says so and OpenSSH asks
   you to confirm the fingerprint. Compare it with the server's own before you answer yes. Your
   answer is kept by OpenSSH, in your own known hosts; FinishUP never changes them. If you say no,
   nothing is added. If the key differs from the one this computer knows, FinishUP refuses at once
   and does not ask.
3. It shows what the server would receive and keep, and what it says about its AI-powered review,
   asks what the server may read outside your projects on this computer (`local` or `listed`;
   `--outside-reads` answers it up front), and asks you to type the server's name.

The server is then added but not in use; `finishup server use lab` chooses it. FinishUP binds your
agreement to the host key OpenSSH verified, and checks it on every connection: if the server's key
changes, FinishUP does not connect, even after your known hosts accept the new key, until you have
checked it and agreed again with `finishup server use lab`.

`server add` refuses with `ssh_path_unusable` when a socket path OpenSSH would be given cannot be
used as written: this computer's FinishUP folder, or the server's FinishUP endpoint, holds `:`,
`%` or `$`. Spaces are fine.

## Add an HTTPS server

```text
finishup server add web https://finishup.example.com
finishup server add web https://finishup.example.com:8443/team --ca-file /path/to/ca.pem
finishup server add port --port 8443 --tls-pin sha256:<64 hex digits>
finishup server add web https://finishup.example.com --key-file /path/to/web.key
```

The address is `https://host[:port][/path]`; the port is 443 unless you give one. Plain `http://`
is refused. `--port PORT` (or `https://127.0.0.1:PORT`, `https://[::1]:PORT`) is a FinishUP server
on a port of this computer; it is still treated as a server elsewhere, because a port on this
computer can forward anywhere. Run the command in your own terminal: you type the server's API key
there, and you confirm what the server may receive by typing its name.

Before you add one, you need from the server's owner:

- **An API key** for you (it starts with `fuk_`), made on the server with
  `finishup service api-key create` (see [Serve this computer over
  HTTPS](#serve-this-computer-over-https)). Its scope decides what you can do there: `agent` covers
  your agents' everyday work, `operator` adds support commands.
- **How to trust its certificate.** By default FinishUP trusts a certificate your computer's
  system store trusts. For a server with its own certificate authority, give that authority's
  certificate with `--ca-file` (PEM certificates, or OpenSSL's trusted certificates as `openssl
  x509 -trustout` writes them, whose trust settings FinishUP keeps); for a self-signed certificate,
  give its fingerprint with
  `--tls-pin sha256:…`: the SHA-256 of the certificate in DER form, as 64 lowercase hex digits
  after `sha256:` (for example from `openssl x509 -in server.pem -outform der | sha256sum`). Give
  at most one of them.
- **The same FinishUP release on the server.** A server whose HTTPS interface differs from this
  release's is refused (`remote_incompatible`) before your key is asked for.

What `server add` does, in order:

1. It asks the server what it is, over HTTPS but without your key, after checking its certificate
   the way you chose. If the address is not a FinishUP server it can work with, it stops there and
   never asks for your key.
2. It asks for the API key on your terminal (`API key for this server (input hidden):`), unless
   `--key-file` names a file that holds it. That file must be readable by you alone; FinishUP reads
   it once and never changes it.
3. It asks the server, with that key, what it offers. A key the server refuses adds nothing.
4. It shows what the server would receive and keep, and what it says about its AI-powered review,
   asks what the server may read outside your projects on this computer (`local` or `listed`;
   `--outside-reads` answers it up front), and asks you to type the server's name.

Only then is the server added, with your agreement and its key. The key is kept in your system's
credential store, or, where there is none, in a file only you can read; it is never shown again,
and never in a command line, a setting, a log or anything your agents see. FinishUP binds your
agreement to the way you chose to trust the server's certificate and to the key: if either changes,
FinishUP does not connect until you agree again.

### The official FinishUP service

```text
finishup server add official
```

`server add official` adds the official FinishUP service this release names, with its address
filled in. This release names none yet, so it refuses (`official_endpoint_unavailable`) and adds
nothing; add a server by its address instead. A server's own claim to be official never counts.
Once one exists, you still agree to it as to any server; it is not asked what it may read outside
your projects and reads there what FinishUP on this computer would, until you choose otherwise with
`finishup server folders mode official listed`.

## Use a server

```text
finishup server use lab
finishup server use local
```

`use NAME` makes every FinishUP client on this computer use that server: your agents' hooks and
FinishUP tools, the `finishup` command and the terminal interface. `use local` goes back to the
everyday FinishUP on this computer.

For a server elsewhere, `use` asks the server again what it offers, shows it and asks you to type
the name each time; for an SSH server OpenSSH may ask about the host key, as at `add`, and an HTTPS
server is asked with the key you stored. After `add` and `use`, FinishUP says whether the project
you are in is held for that server (see
[Servers elsewhere and your privacy policy](#servers-elsewhere-and-your-privacy-policy)).

Restart agent sessions that are already open. An open session's FinishUP tools keep the server
on this computer they started with, while its hooks follow the new choice at once. A session
connected to a server on another machine ends that connection when you choose another server, and
its next FinishUP call follows your choice.

Your agent hosts need nothing new: Claude Code, Codex and Cursor keep their existing connection and
follow your choice. A test copy of FinishUP that runs in its own folder is not affected by the
choice, and `server use` refuses while such a setting decides which FinishUP is used.

## Check a server

```text
finishup server list
finishup server status lab
finishup server status --json
finishup server test lab
```

`list` shows every server and which one is in use. `status` shows which setting chose the server
in use, its kind, its state (for example ready, locked or not running), its FinishUP release and
its vault mode. `test` connects, measures the round trip and warns when it is slow enough that a startup
check required by your agent setup would likely time out.

For an SSH or HTTPS server, `status` also shows how this computer reaches it and what FinishUP's
helper last did, for example:

```text
Connection: relay (this computer's FinishUP helper keeps one SSH connection for every program here).
Helper: running; last ready.
```

For an HTTPS server it also says whether an API key is stored (`API key: keyring`, `file` or
`none`), never the key itself.

## How this computer reaches a server elsewhere

FinishUP runs one small background **helper** per SSH or HTTPS server on this computer. It starts
when something first needs the server and stops by itself 15 minutes after the last program used
it. It also answers the server's questions about your project while the server is still working on
it (for example during a review), and delivers what your agents' hooks captured for observation.

There are two ways for your programs to reach the server:

- **relay** (the default): the helper keeps one connection, and every program here goes through
  it. For an HTTPS server the helper is the only program that reads its API key.
- **direct** (advanced): each program here (hooks, FinishUP tools, commands) connects to the server
  itself: over SSH, its own channel through one OpenSSH connection that stays open for 15 minutes;
  over HTTPS, its own connection, **so each of those programs reads the API key**. The helper still
  answers the server's background work.

```text
finishup server set lab --style direct
finishup server set lab --style relay
```

You can choose only a way the server offers. Changing it stops the helper (and, for SSH, the SSH
connection) first; restart open agent sessions afterwards.

## Log in and out of an HTTPS server

```text
finishup server login web
finishup server login web --key-file /path/to/new.key
finishup server logout web
```

`login` stores a new API key for an HTTPS server, for example when its owner gave you a new one.
You type it on your own terminal, or `--key-file` names a file only you can read. FinishUP asks the
server about the key before it keeps it:

- a key the server refuses, a server whose certificate no longer matches the trust you chose, or a
  server FinishUP cannot work with: nothing is stored, and FinishUP says why;
- a server that does not answer: the key is stored, "not verified yet", and FinishUP sends nothing
  to that server until the key is checked: once the server is up, run `finishup server use NAME`
  (it checks the key and asks you again), or log in again.
- if storing the key fails part way (a full disk, say), FinishUP says so and sends nothing to that
  server until a key is checked: run `finishup server login NAME` again, then `finishup server use
  NAME`.

Storing a key ends every connection made with the old one, the helper's included. A new key is a
new identity at the server, so FinishUP then asks you to agree again with `finishup server use
NAME` before it connects.

`logout` deletes the stored key on this computer and stops the helper; it sends nothing. Until you
log in again, requests to that server are refused (`remote_auth_failed`). `login` and `logout` do
not apply to an SSH server, which uses your OpenSSH keys.

## Connect and disconnect

```text
finishup server connect lab
finishup server disconnect lab
```

FinishUP starts a server's service on demand, so you rarely need these. For a server on this
computer (`local`, a named local server, or no name while this computer's own server is in use),
`connect` starts its FinishUP service and `disconnect` stops it, as `finishup service stop` does,
including any check or review it was still running; it starts again on demand.

For an SSH or HTTPS server, `connect` checks that you may use it and connects (starting the
helper), and `disconnect` stops this computer's helper (and, for SSH, its SSH connection). The
server's own FinishUP keeps running; stop it on the server if you want to. The next use connects
again.

## Remove a server

```text
finishup server remove lab
finishup server remove lab --select-local
```

`remove` stops the server's service and removes everything FinishUP kept on this computer for that
server. Removing a named local server deletes its tasks and vault, and nothing in FinishUP can
recover them afterwards; back it up first if you may want it again. `remove` refuses the server you
are using unless you add `--select-local`, which switches back to the everyday server first. If
the service does not stop in time, `remove` keeps the server and asks you to run it again. The
switch back to the everyday server stays, and `remove` says so. An agent session that was still
using the removed server stops reaching FinishUP and says so until you restart it.

For an SSH or HTTPS server, `remove` stops this computer's helper (and SSH connection) and removes
what FinishUP kept on this computer for it, an HTTPS server's API key included; nothing on the
server is deleted, and its tasks stay there.

If adding or removing a server was interrupted, or something changed a server's folder while
`remove` deleted it (`remove` then says so), `list` may name a leftover folder (`t_` and eight
characters) that holds no server. FinishUP does not use it; `finishup server remove` with that
name deletes it.

## The terminal interface

The header shows which server is in use when it is not the everyday one, and `/server` lists your
servers and switches between them. Adding a server there offers a server on this computer and
prints the `finishup server add NAME --local` command for you to run in your shell; add an SSH
server with `finishup server add NAME ssh://…` in your shell too, where OpenSSH can ask about its
host key, and an HTTPS server with `finishup server add NAME https://…`, where you type its API
key. Choosing an SSH or HTTPS server in `/server` asks you to agree there, but OpenSSH cannot ask
about an unknown host key on that screen: add or use an SSH server once in your shell first.
Removing a server, and logging in or out, happen in your shell.

## Servers elsewhere and your privacy policy

These rules apply to every server elsewhere: an SSH server, or an HTTPS server on the web or on a
port of this computer.

- **A project whose privacy policy here allows no network use is held.** While a server elsewhere
  is selected, FinishUP sends nothing it reads or claims for such a project to that server until
  you decide. Your agent asks you once; only you can allow it, from your own terminal, and you can
  instead keep the project on this computer so FinishUP does not ask again. Observations captured
  while it was held wait on this computer; after you allow it they are sent, without the content
  captured while it was held.
- **What this computer records for it.** FinishUP keeps, in a file only you can read beside its
  server list, what its own privacy policy said of each project (whether it allows network use,
  since when, and up to eight folders of each project). It starts keeping this only when you first
  add a server elsewhere, so there is nothing from before then; removing your last server
  elsewhere deletes it.
- **A connection ends when what it was made under changes.** Choosing another server, removing
  the server, or logging in or out of it ends any open connection to it within about a second, the
  helper's included; a request already under way may finish. The next request is made under your
  current choice.
- **No network while this computer's policy forbids it.** While this computer's privacy policy
  allows no network use, FinishUP refuses to add, choose or reach a server elsewhere, and the
  helper stops.
- **Honest limits.** A project FinishUP has not yet heard about is not held. The hold covers what
  FinishUP itself reads and claims for the project, not what an agent working in another folder
  reads and its hooks capture. A project inside another project follows the outer project's
  policy.

## Keeping a copy of your code on a server (level L2)

**Not available in this release.** No FinishUP server keeps a copy of your code yet, and FinishUP
never sends one: a server elsewhere reads your project only through FinishUP on this computer, while
it works. This section says what keeping a copy will mean once a later release offers it.

When a server offers it, FinishUP will show what it means and ask you to agree on your own
terminal. Then:

- **What is sent.** A copy of each project you use with that server: the files git can see
  (tracked, and untracked but not ignored), never the project's history. Files with names that are
  always left out (environment files such as `.env`, SSH keys such as `id_rsa`, `.netrc`, `.npmrc`,
  `*.pem` and `*.key` files, cloud and Kubernetes credentials, Terraform state and similar), the
  server's own exclusions and the list you keep for the project are not sent. The **names** of the
  files left out are sent, never their contents.
- **What is scanned.** Before a file is sent, FinishUP checks its contents for known secret
  formats (private keys, access tokens of common services, passwords written into URLs). A file
  that matches is held back until you allow that exact content. Names and scans reduce what is sent;
  they are not a guarantee that no secret is.
- **What is kept, and for how long.** The server keeps the copy encrypted, readable only while its
  vault is unlocked, for as long as you chose among the options it offers (for example a number of
  days after the last update, or until you forget it). The server's owner controls that server:
  locking its vault does not take back anything already read out of it, and FinishUP does not
  manage backups of it.
- **How forget works.** In a later release, `finishup server code forget` asks the server to
  delete its copy of the project you are in and says exactly what it deleted. Each project's copy
  is forgotten on its own. Evidence already recorded in your tasks there, such as captured changes
  and review excerpts, is not part of the copy.
- **Stopping is not forgetting.** Holding a project, keeping one project's code on this computer
  while the server keeps its tasks (as today, level L1), choosing another server or removing the
  server only stops future sends; what was already sent stays on the server until you forget it or
  its time runs out.

## Serve this computer over HTTPS

To let your other computers use the FinishUP on this one over HTTPS, give each of them an API key
and run FinishUP's HTTPS server here. Both are commands for this computer's own terminal.

```text
finishup service api-key create --label laptop --scope agent
finishup service api-key create --label ci --scope agent --output-file ci.key --expires-in-days 90
finishup service rest run --listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
```

**API keys.** `api-key create` makes a key and shows it once, on your terminal, or writes it to a
new file only you can read (`--output-file`; an existing file is never overwritten). FinishUP keeps
only a salted hash of it, so a lost key cannot be shown again: make a new one. A key that could not
be shown or written is revoked at once.

- `--scope agent` covers what your agents and their hooks do (starting tasks, publishing work,
  checks, responses, status and receipts). `--scope operator` also allows support commands such as
  `project`, `review`, importing a Codex transcript, observation status, locking the service, and
  reading, proposing or tightening the privacy policy. Some things are never done over HTTPS
  whatever the scope: stopping the service, backup, restore, migration, host integration, pausing,
  resuming or revoking observation, unlocking the vault and approving a privacy change.
- `finishup service api-key list` shows each key's id, label, scope and whether it is active,
  revoked or expired, never the key.
- `finishup service api-key revoke KEY_ID` revokes one: its next request fails, and its open
  connections end.
- `finishup service api-key create --rotate KEY_ID` makes a replacement that keeps the old key's
  label, scope and the tasks its computer started; log that computer in with it (`finishup server
  login NAME` there), then revoke the old key.

Each key keeps its projects apart: the same project used through two different keys, or over HTTPS
and over SSH, becomes two separate sets of tasks here. Keys are not a wall between people yet:
anyone holding a key of this server can read a task whose id they know. Give keys only to
computers you trust as you trust this one.

**Running the server.** `service rest run` runs in the foreground until you press Ctrl-C or stop
it; run it under a supervisor of your own to keep it running. It needs a certificate and its key
(`--tls-cert`, `--tls-key`; the key file must be readable by you alone) and speaks TLS 1.2 or later.
There are two ways to run it:

- **gateway** (the default): a separate program of your user, without your vault, that passes each
  request to this computer's FinishUP service and starts the service when a request needs it.
- **native** (`--edge native`): the service itself listens, so the program that holds your vault is
  on the network. Choose it only after your own security review. Stop the running service first
  (`finishup service stop`); a passphrase vault is then unlocked with `finishup service unlock` on
  this computer, as usual.

Behind a reverse proxy that handles TLS on this computer, use `--behind-proxy` instead of the
certificate: FinishUP then serves plain HTTP on a loopback address only (for example `--listen
127.0.0.1:8080`). FinishUP writes one line per request to `rest-audit.jsonl` in its log folder
(what was asked and how it ended, never what was sent, a key or an address), and keeps it small.

| You see | What it means | What to do |
|---|---|---|
| `rest_tls_required` | Neither a certificate nor `--behind-proxy` was given. | Give `--tls-cert` and `--tls-key`, or `--behind-proxy` on a loopback address. |
| `rest_tls_unusable` | The certificate and key could not be loaded together, or the key file can be read by others. | Check the pair, and make the key file readable by you alone (`chmod 600`). |
| `rest_proxy_not_loopback` | `--behind-proxy` was given with an address other than loopback. | Listen on `127.0.0.1` or `[::1]` behind your proxy. |
| `rest_listen_invalid` | `--listen` is not `HOST:PORT` with an IP address or `localhost`. | For example `--listen 0.0.0.0:8443`; port 0 picks a free one. |
| `rest_listener_unavailable` | That address could not be used (in use, or not this computer's). | Choose another port or address. |
| `service_already_running` | `--edge native` runs the service itself, and it is already running. | Stop it first (`finishup service stop`), or use the default gateway beside it. |
| `api_key_output_exists` | `--output-file` names a file that already exists. | Choose a new path; a key is never written over a file. |
| `trusted_console_required` | A key is shown only on your own terminal, and the command ran without one; no key was made. | Run the command in your own terminal, or pass `--output-file`. |
| `api_key_not_shown`, `api_key_output_failed` | The new key could not be shown, or written to the file, so it was revoked at once and nobody can use it. | Run the command again in your own terminal, or with a new `--output-file` path. |
| `api_keys_damaged`, `api_keys_unsafe` | FinishUP's file of API keys is damaged, or can be read by others. | Fix its permissions, or move it aside and make new keys. |

## Not supported yet

- Keeping a copy of your code on the server (see
  [Keeping a copy of your code on a server](#keeping-a-copy-of-your-code-on-a-server-level-l2)); a
  server elsewhere reads your code only through FinishUP on this computer.
- Adding an SSH or HTTPS server from the terminal interface (use your shell).
- Signing in to an HTTPS server with anything other than an API key (for example OAuth).
- An official FinishUP service: this release names none.
- An SSH host certificate in place of a host key: FinishUP refuses such a server
  (`remote_identity_changed`).
- SSH and HTTPS servers have been tried on Linux. macOS, and Windows through WSL 2, have not been
  tested yet as either end of an SSH or HTTPS server; on macOS a Python from python.org may need
  its certificates installed before FinishUP trusts a server through the system store.

## Troubleshooting

FinishUP never quietly falls back to another FinishUP when the server in use cannot be reached,
and it never keeps a request of yours or your agent's to send later: a call that could not reach
the server says so and can be repeated safely. What your agent's hooks capture for observation is
the one thing that waits on purpose: it stays on this computer and is delivered by a later hook or
by FinishUP's background delivery once the server answers (`finishup observe drain` delivers it
now).

| You see | What it means | What to do |
|---|---|---|
| `remote_kind_unavailable` | You gave `finishup server add` an address this release cannot use (for example `http://…`). Nothing was added or sent, and the server in use did not change. | Add a named local server with `finishup server add NAME --local`, an SSH server with `finishup server add NAME ssh://[user@]host[:port]`, or an HTTPS server with `finishup server add NAME https://host[:port]` (or `--port PORT` on this computer). |
| `official_endpoint_unavailable` | `finishup server add official` was used, but this release names no official FinishUP service yet. Nothing was added. | Add a server by its address: `finishup server add NAME https://HOST`. |
| `credential_not_applicable` | `finishup server login`, `logout` or `--key-file` was used for an SSH server, which uses your OpenSSH keys, not an API key. | Load your SSH key in your SSH agent (`ssh-add`) instead. |
| `remote_launcher_not_found` | `server add` found no FinishUP on the server at the usual install paths. Nothing was added. | Install the same FinishUP release on the server, or give its full path with `--remote-launcher`. |
| `remote_host_key_unconfirmed` | OpenSSH asked you to confirm the server's host key and you declined or did not answer. Nothing was added. | Check the fingerprint with the server's own, then run `finishup server add` again and answer yes. |
| `trusted_console_required` | Adding or choosing a server elsewhere, or typing an API key, needs your own terminal: the command ran without one (for example from an agent's shell), or OpenSSH would have had to ask about a host key where it cannot. | Run the command yourself in your own terminal (or give an HTTPS key with `--key-file`). |
| `remote_identity_changed` | The server's SSH host key is not the one this computer knows (or it uses a host certificate), or an HTTPS server's certificate does not match the trust you chose (the system store, `--ca-file` or `--tls-pin`), so FinishUP did not connect and sent nothing. | Check the server's key or certificate another way. For SSH, if it really changed, update it with OpenSSH's own tools (for example `ssh-keygen -R`) and agree again with `finishup server use NAME`; for HTTPS, remove the server and add it again with the right trust. Never turn off host key or certificate checking. |
| `remote_auth_failed` | The server refused the SSH keys OpenSSH offered, or an HTTPS server refused this computer's API key (unknown, revoked or expired), or no API key is stored for it (after `server logout`), or the system's credential store did not answer in time. | For SSH, load your key in your SSH agent (`ssh-add`), or check that it is authorized for that account on the server. For HTTPS, ask the server's owner for a valid key and run `finishup server login NAME`; unlock your system's credential store if it is locked. Then repeat the request. |
| `remote_unreachable` | FinishUP could not reach the server over SSH or HTTPS, or the connection ended. | Check the address and your network; `finishup server test NAME` shows whether it answers now. |
| `remote_service_not_running` | The server answered, but its FinishUP service is not running and could not be started (for HTTPS, its HTTPS server answered but could not reach the service). | Start it on the server (`finishup service start` there), then repeat the request. |
| `remote_incompatible` | The server runs another FinishUP release than this computer, or, over HTTPS, it does not serve this release's HTTPS interface or is not a FinishUP server at all. Nothing was recorded there, and `server add` never asked for your key. | Install the same FinishUP release on both machines, and check the address. |
| `style_unavailable` | `finishup server set NAME --style` named a way the server does not offer. Nothing was changed. | `finishup server status NAME` shows the server; keep the current way. |
| `target_still_connected` | This computer's helper for that server did not stop in time, so nothing was changed or removed. | Run the same command again. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer, or an agent session that was open when you removed its server still uses it. | Run `finishup server use local` (or choose another server) and restart open agent sessions. For a damaged folder, also remove the server and add it again. |
| `selection_invalid` | The saved server choice is damaged, or names a server whose folder on this computer is missing or unsafe. `finishup server` commands say this instead of `isolation_root_invalid`. | Run `finishup server use local`; it clears the choice even when it cannot be read. |
| `repository_egress_held` | A server elsewhere is selected and this project's privacy policy on this computer allows no network use, so FinishUP refused the connection before anything from it was sent. | Decide once: allow it from your own terminal in that project, or keep it on this computer so FinishUP does not ask again. |
| `repository_egress_kept` | You chose to keep this project on this computer for the selected server elsewhere. | Nothing to do; FinishUP does not ask again. |
| `server_authorization_changed` | Something a connection to a server elsewhere was allowed under changed while it was open (the server choice, the server's record or key, a `server login` or `logout`, this computer's privacy policy, or a project's hold), so FinishUP stopped sending over it. What that server already received stays there. A request that was already on its way may or may not have been recorded there; FinishUP does not send it again, since your current choice may be another server. | Later requests use your current choice, or say what refuses it now. If that request was a change, check whether it was recorded before you make it again. |
| `server_profile_changed` | What that server offers or needs (for example whether its AI-powered review sends what it reads to a model provider) changed since you agreed to use it, you logged in with a new API key, or FinishUP could not confirm it, so that server did no work for this request. Another request already on its way over the same connection ends with `server_authorization_changed`: it may or may not have been recorded there. | Agree again in your own terminal with `finishup server use NAME`, or go back with `finishup server use local`. |
| `server_level_unavailable` | That server requires more of this computer than you agreed to (for example keeping a copy of your code), so nothing was sent for this project. | `finishup server use NAME` shows what it requires; or use another server. |
| `target_root_is_remote` | Something tried to start or reach a FinishUP service for a server whose record on this computer cannot be read; or a command that runs only where the server lives (setup, for example) ran while a server elsewhere is in use. FinishUP refuses, starts nothing and sends nothing; setup stops before it looks for agents, asks anything or changes any agent's settings. | Run `finishup server use local` to use this computer's FinishUP, then start a new agent session: an open one keeps the server it started with. If `FINISHUP_ISOLATED_ROOT` or a pinned test copy names that server, `server use` cannot change it: unset the variable or run your everyday installation instead, then start a new agent session. |
| `workspace_binding_conflict` | A request named the project in a form its connection cannot use, such as a `client:` handle sent to a FinishUP on this computer. | Name the project by its folder path through FinishUP's own tools; a hand-written client must not send a `client:` handle to a server on this computer. |
