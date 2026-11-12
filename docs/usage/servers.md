# FinishUP servers

By default FinishUP runs one service on your own computer, and your agents, the `finishup`
command and the terminal interface all use it. A **server** lets them use a different FinishUP
service instead: a **named local server** on this computer, with its own tasks, settings and
vault, or **your own FinishUP server on another machine, over SSH**.

Nothing changes until you add a server and choose to use it. Without one, FinishUP behaves exactly
as it always has.

This release connects to FinishUP servers on this computer (the everyday server and the named
local servers you add) and to FinishUP servers on another machine over SSH. Servers on the web
(over HTTPS) and on a port of this computer arrive in a later release; until then `finishup server
add` refuses them before it asks you anything or connects anywhere, and nothing is added (see
[Troubleshooting](#troubleshooting)).

## Add a server

```text
finishup server add lab --local
```

A name is up to 16 lowercase letters, digits and hyphens, starting with a letter or digit. `local`
is reserved: it always means the everyday FinishUP on this computer. FinishUP shows a server's
name where you manage servers yourself: the `finishup server` commands (`add`, `use`, `list`,
`status`, `test`, `connect`, `disconnect`, `set` and `remove`) and `/server` in the terminal
interface.
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

## Use a server

```text
finishup server use lab
finishup server use local
```

`use NAME` makes every FinishUP client on this computer use that server: your agents' hooks and
FinishUP tools, the `finishup` command and the terminal interface. `use local` goes back to the
everyday FinishUP on this computer.

For a server on another machine, `use` asks the server again what it offers, shows it and asks you
to type the name each time; OpenSSH may ask about the host key, as at `add`. After `add` and
`use`, FinishUP says whether the project you are in is held for that server (see
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

For an SSH server, `status` also shows how this computer reaches it and what FinishUP's helper
last did, for example:

```text
Connection: relay (this computer's FinishUP helper keeps one SSH connection for every program here).
Helper: running; last ready.
```

A server that another FinishUP release added for HTTPS or a port shows in `list` and `status` as
not available in this release. FinishUP does not use it: choosing it is refused, and the server in
use stays as it was. `finishup server remove NAME` removes it.

## How this computer reaches an SSH server

FinishUP runs one small background **helper** per SSH server on this computer. It starts when
something first needs the server and stops by itself 15 minutes after the last program used it.
It also answers the server's questions about your project while the server is still working on
it (for example during a review), and delivers what your agents' hooks captured for observation.

There are two ways for your programs to reach the server:

- **relay** (the default): the helper keeps one SSH connection, and every program here goes
  through it.
- **direct** (advanced): each program here (hooks, FinishUP tools, commands) opens its own SSH
  channel, through one OpenSSH connection that stays open for 15 minutes; the helper still answers
  the server's background work.

```text
finishup server set lab --style direct
finishup server set lab --style relay
```

You can choose only a way the server offers. Changing it stops the helper and the SSH connection
first; restart open agent sessions afterwards.

## Connect and disconnect

```text
finishup server connect lab
finishup server disconnect lab
```

FinishUP starts a server's service on demand, so you rarely need these. For a server on this
computer (`local`, a named local server, or no name while this computer's own server is in use),
`connect` starts its FinishUP service and `disconnect` stops it, as `finishup service stop` does,
including any check or review it was still running; it starts again on demand.

For an SSH server, `connect` checks that you may use it and connects (starting the helper), and
`disconnect` stops this computer's helper and its SSH connection. The server's own FinishUP keeps
running; stop it on the server if you want to. The next use connects again.

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

For an SSH server, `remove` stops this computer's helper and SSH connection and removes what
FinishUP kept on this computer for it; nothing on the server is deleted, and its tasks stay there.

If adding or removing a server was interrupted, or something changed a server's folder while
`remove` deleted it (`remove` then says so), `list` may name a leftover folder (`t_` and eight
characters) that holds no server. FinishUP does not use it; `finishup server remove` with that
name deletes it.

## The terminal interface

The header shows which server is in use when it is not the everyday one, and `/server` lists your
servers and switches between them. Adding a server there offers a server on this computer and
prints the `finishup server add NAME --local` command for you to run in your shell; add an SSH
server with `finishup server add NAME ssh://…` in your shell too, where OpenSSH can ask about its
host key. Choosing an SSH server in `/server` asks you to agree there, but OpenSSH cannot ask
about an unknown host key on that screen: add or use the server once in your shell first.
Removing a server happens in your shell.

## Servers elsewhere and your privacy policy

These rules apply to every server elsewhere; in this release that means an SSH server.

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
- **A connection ends when what it was made under changes.** Choosing another server or removing
  the server ends any open connection to it within about a second, the helper's included; a
  request already under way may finish. The next request is made under your current choice.
- **No network while this computer's policy forbids it.** While this computer's privacy policy
  allows no network use, FinishUP refuses to add, choose or reach a server elsewhere, and the
  helper stops.
- **Honest limits.** A project FinishUP has not yet heard about is not held. The hold covers what
  FinishUP itself reads and claims for the project, not what an agent working in another folder
  reads and its hooks capture. A project inside another project follows the outer project's
  policy.

## Not supported yet

- Servers on the web (HTTPS) and on a port of this computer, and signing in to a server with a key
  (`finishup server login`).
- Keeping a copy of your code on the server; a server elsewhere reads your code only through
  FinishUP on this computer.
- Adding an SSH server from the terminal interface (use your shell).
- An SSH host certificate in place of a host key: FinishUP refuses such a server
  (`remote_identity_changed`).
- SSH servers have been tried on Linux. macOS, and Windows through WSL 2, have not been tested yet
  as either end of an SSH server.

## Troubleshooting

FinishUP never quietly falls back to another FinishUP when the server in use cannot be reached,
and it never keeps a request of yours or your agent's to send later: a call that could not reach
the server says so and can be repeated safely. What your agent's hooks capture for observation is
the one thing that waits on purpose: it stays on this computer and is delivered by a later hook or
by FinishUP's background delivery once the server answers (`finishup observe drain` delivers it
now).

| You see | What it means | What to do |
|---|---|---|
| `remote_kind_unavailable` | You gave `finishup server add` a web address (`https://…`), a port (`--port`) or an address that is not `ssh://…`, or chose a server another FinishUP release added for the web or a port. This release connects to FinishUP servers on this computer and over SSH. Nothing was added or sent, and the server in use did not change. | Use the everyday server (`finishup server use local`), add a named local server with `finishup server add NAME --local`, or an SSH server with `finishup server add NAME ssh://[user@]host[:port]`. Servers on the web and on a port arrive in a later release. |
| `remote_launcher_not_found` | `server add` found no FinishUP on the server at the usual install paths. Nothing was added. | Install the same FinishUP release on the server, or give its full path with `--remote-launcher`. |
| `remote_host_key_unconfirmed` | OpenSSH asked you to confirm the server's host key and you declined or did not answer. Nothing was added. | Check the fingerprint with the server's own, then run `finishup server add` again and answer yes. |
| `trusted_console_required` | Adding or choosing a server elsewhere needs your own terminal: the command ran without one (for example from an agent's shell), or OpenSSH would have had to ask about a host key where it cannot. | Run the command yourself in your own terminal. |
| `remote_identity_changed` | The server's SSH host key is not the one this computer knows (or it uses a host certificate), so FinishUP did not connect and sent nothing. | Check the server's key another way. If it really changed, update it with OpenSSH's own tools (for example `ssh-keygen -R`) and agree again with `finishup server use NAME`, or remove the server and add it again. Never turn off host key checking. |
| `remote_auth_failed` | The server refused the SSH keys OpenSSH offered. | Load your key in your SSH agent (`ssh-add`), or check that it is authorized for that account on the server, then repeat the request. |
| `remote_unreachable` | FinishUP could not reach the server over SSH, or the connection ended. | Check the address and your network; `finishup server test NAME` shows whether it answers now. |
| `remote_service_not_running` | The server answered over SSH, but its FinishUP service is not running and could not be started. | Start it on the server (`finishup service start` there), then repeat the request. |
| `remote_incompatible` | The server runs another FinishUP release than this computer. Nothing was recorded there. | Install the same FinishUP release on both machines. |
| `style_unavailable` | `finishup server set NAME --style` named a way the server does not offer. Nothing was changed. | `finishup server status NAME` shows the server; keep the current way. |
| `target_still_connected` | This computer's helper for that server did not stop in time, so nothing was changed or removed. | Run the same command again. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer, or an agent session that was open when you removed its server still uses it. | Run `finishup server use local` (or choose another server) and restart open agent sessions. For a damaged folder, also remove the server and add it again. |
| `selection_invalid` | The saved server choice is damaged, or names a server whose folder on this computer is missing or unsafe. `finishup server` commands say this instead of `isolation_root_invalid`. | Run `finishup server use local`; it clears the choice even when it cannot be read. |
| `repository_egress_held` | A server elsewhere is selected and this project's privacy policy on this computer allows no network use, so FinishUP refused the connection before anything from it was sent. | Decide once: allow it from your own terminal in that project, or keep it on this computer so FinishUP does not ask again. |
| `repository_egress_kept` | You chose to keep this project on this computer for the selected server elsewhere. | Nothing to do; FinishUP does not ask again. |
| `server_authorization_changed` | Something a connection to a server elsewhere was allowed under changed while it was open (the server choice, the server's record or key, this computer's privacy policy, or a project's hold), so FinishUP stopped sending over it. What that server already received stays there. A request that was already on its way may or may not have been recorded there; FinishUP does not send it again, since your current choice may be another server. | Later requests use your current choice, or say what refuses it now. If that request was a change, check whether it was recorded before you make it again. |
| `server_profile_changed` | What that server offers or needs (for example whether its AI-powered review sends what it reads to a model provider) changed since you agreed to use it, or FinishUP could not confirm it, so that server did no work for this request. Another request already on its way over the same connection ends with `server_authorization_changed`: it may or may not have been recorded there. | Agree again in your own terminal with `finishup server use NAME`, or go back with `finishup server use local`. |
| `server_level_unavailable` | That server requires more of this computer than you agreed to (for example keeping a copy of your code), so nothing was sent for this project. | `finishup server use NAME` shows what it requires; or use another server. |
| `target_root_is_remote` | Something tried to start or reach a FinishUP service for a server that another FinishUP release added for the web or a port, or whose record on this computer cannot be read; or a command that runs only where the server lives (setup, for example) ran while a server elsewhere is in use. FinishUP refuses, starts nothing and sends nothing; setup stops before it looks for agents, asks anything or changes any agent's settings. | Run `finishup server use local` to use this computer's FinishUP, then start a new agent session: an open one keeps the server it started with. If `FINISHUP_ISOLATED_ROOT` or a pinned test copy names that server, `server use` cannot change it: unset the variable or run your everyday installation instead, then start a new agent session. |
| `workspace_binding_conflict` | A request named the project in a form its connection cannot use, such as a `client:` handle sent to a FinishUP on this computer. | Name the project by its folder path through FinishUP's own tools; a hand-written client must not send a `client:` handle to a server on this computer. |
| `workspace_ref_not_served` | With a FinishUP server on another machine, a task named another project folder than the one FinishUP was started in: another repository, or another worktree of the same one. That server reads only the project FinishUP was started in (a subfolder of it, or the same folder spelled another way, is the same project), so the request was not sent and nothing of either project was read or copied for it. | Run the command, or start the agent session, in the project the task is about. An agent whose FinishUP tools were started in another folder tells you so and carries on without FinishUP for that project; open a session in that project to use FinishUP there. |
