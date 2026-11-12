# FinishUP servers

By default FinishUP runs one service on your own computer, and your agents, the `finishup`
command and the terminal interface all use it. A **server** lets them use a different FinishUP
service on this computer instead: a **named local server**, with its own tasks, settings and
vault.

Nothing changes until you add a server and choose to use it. Without one, FinishUP behaves exactly
as it always has.

This release connects only to FinishUP servers on this computer: the everyday server and the named
local servers you add. Servers on another machine (over SSH), on the web (over HTTPS) and on a port
of this computer arrive in a later release. Until then `finishup server add` refuses them before it
asks you anything or connects anywhere, and nothing is added (see
[Troubleshooting](#troubleshooting)).

## Add a server

```text
finishup server add lab --local
```

A name is up to 16 lowercase letters, digits and hyphens, starting with a letter or digit. `local`
is reserved: it always means the everyday FinishUP on this computer. FinishUP shows a server's
name where you manage servers yourself: the `finishup server` commands (`add`, `use`, `list`,
`status`, `test`, `connect`, `disconnect` and `remove`) and `/server` in the terminal interface.
Error codes, logs and receipts name a server only by a short id such as `t_1a2b3c4d`.

A named local server is a second FinishUP on this computer, with its own tasks, vault, privacy
policy and AI-powered review settings. It starts when something first needs it, like the everyday
one. It needs its own setup: choose it (below) and run `finishup setup`, exactly as for a first
installation.

## Use a server

```text
finishup server use lab
finishup server use local
```

`use NAME` makes every FinishUP client on this computer use that server: your agents' hooks and
FinishUP tools, the `finishup` command and the terminal interface. `use local` goes back to the
everyday FinishUP on this computer.

Restart agent sessions that are already open. An open session's FinishUP tools keep the server
on this computer they started with, while its hooks follow the new choice at once. Once servers
elsewhere arrive, a session connected to one ends that connection when you choose another server,
and its next FinishUP call follows your choice.

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

A server that another FinishUP release added for SSH, HTTPS or a port shows in `list` and `status`
as not available in this release. FinishUP does not use it: choosing it is refused, and the server
in use stays as it was. `finishup server remove NAME` removes it.

## Connect and disconnect

```text
finishup server connect lab
finishup server disconnect lab
```

FinishUP starts a server's service on demand, so you rarely need these. For a server on this
computer (`local`, a named local server, or no name while this computer's own server is in use),
`connect` starts its FinishUP service and `disconnect` stops it, as `finishup service stop` does,
including any check or review it was still running; it starts again on demand.

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

If adding or removing a server was interrupted, or something changed a server's folder while
`remove` deleted it (`remove` then says so), `list` may name a leftover folder (`t_` and eight
characters) that holds no server. FinishUP does not use it; `finishup server remove` with that
name deletes it.

## The terminal interface

The header shows which server is in use when it is not the everyday one, and `/server` lists your
servers and switches between them. Adding a server there offers a server on this computer and
prints the `finishup server add NAME --local` command for you to run in your shell; removing one
happens in your shell too.

## Servers elsewhere and your privacy policy

These rules are built into this release and apply once servers on another machine, on the web or
on a port arrive; until then none of them can stop anything you do.

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
  the server or signing out of it ends any open connection to it within about a second; a request
  already under way may finish. The next request is made under your current choice.
- **Honest limits.** A project FinishUP has not yet heard about is not held. The hold covers what
  FinishUP itself reads and claims for the project, not what an agent working in another folder
  reads and its hooks capture. A project inside another project follows the outer project's
  policy.

## Troubleshooting

FinishUP never quietly falls back to another FinishUP when the server in use cannot be reached,
and it never keeps a request of yours or your agent's to send later: a call that could not reach
the server says so and can be repeated safely. What your agent's hooks capture for observation is
the one thing that waits on purpose: it stays on this computer and is delivered by a later hook or
by FinishUP's background delivery once the server answers (`finishup observe drain` delivers it
now).

| You see | What it means | What to do |
|---|---|---|
| `remote_kind_unavailable` | You gave `finishup server add` an SSH address (`ssh://…`), a web address (`https://…`) or a port (`--port`), or chose a server another FinishUP release added for one of them. This release connects only to FinishUP servers on this computer. Nothing was added or sent, and the server in use did not change. | Use the everyday server (`finishup server use local`), or add a named local server with `finishup server add NAME --local`. Servers on another machine, on the web and on a port arrive in a later release. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer, or an agent session that was open when you removed its server still uses it. | Run `finishup server use local` (or choose another server) and restart open agent sessions. For a damaged folder, also remove the server and add it again. |
| `selection_invalid` | The saved server choice is damaged, or names a server whose folder on this computer is missing or unsafe. `finishup server` commands say this instead of `isolation_root_invalid`. | Run `finishup server use local`; it clears the choice even when it cannot be read. |
| `repository_egress_held` | A server elsewhere is selected and this project's privacy policy on this computer allows no network use, so FinishUP refused the connection before anything from it was sent. (Servers elsewhere arrive in a later release.) | Decide once: allow it from your own terminal in that project, or keep it on this computer so FinishUP does not ask again. |
| `repository_egress_kept` | You chose to keep this project on this computer for the selected server elsewhere. | Nothing to do; FinishUP does not ask again. |
| `server_authorization_changed` | Something a connection to a server elsewhere was allowed under changed while it was open (the server choice, the server's record or key, this computer's privacy policy, or a project's hold), so FinishUP stopped sending over it. What that server already received stays there. A request that was already on its way may or may not have been recorded there; FinishUP does not send it again, since your current choice may be another server. | Later requests use your current choice, or say what refuses it now. If that request was a change, check whether it was recorded before you make it again. |
| `server_profile_changed` | What that server offers or needs (for example whether its AI-powered review sends what it reads to a model provider) changed since you agreed to use it, or FinishUP could not confirm it, so that server did no work for this request. Another request already on its way over the same connection ends with `server_authorization_changed`: it may or may not have been recorded there. | Agree again in your own terminal with `finishup server use NAME`, or go back with `finishup server use local`. |
| `server_level_unavailable` | That server requires more of this computer than you agreed to (for example keeping a copy of your code), so nothing was sent for this project. | `finishup server use NAME` shows what it requires; or use another server. |
| `target_root_is_remote` | Something tried to start or reach a FinishUP service for a server that another FinishUP release added for another machine, the web or a port. FinishUP refuses, starts nothing and sends nothing; setup stops before it looks for agents, asks anything or changes any agent's settings. | Run `finishup server use local` to use this computer's FinishUP, then start a new agent session: an open one keeps the server it started with. If `FINISHUP_ISOLATED_ROOT` or a pinned test copy names that server, `server use` cannot change it: unset the variable or run your everyday installation instead, then start a new agent session. |
| `workspace_binding_conflict` | A request named the project in a form its connection cannot use, such as a `client:` handle sent to a FinishUP on this computer. | Name the project by its folder path through FinishUP's own tools; a hand-written client must not send a `client:` handle to a server on this computer. |
| `workspace_ref_not_served` | With a FinishUP server on another machine, a task named another project folder than the one FinishUP was started in: another repository, or another worktree of the same one. That server reads only the project FinishUP was started in (a subfolder of it, or the same folder spelled another way, is the same project), so the request was not sent and nothing of either project was read or copied for it. | Run the command, or start the agent session, in the project the task is about. An agent whose FinishUP tools were started in another folder tells you so and carries on without FinishUP for that project; open a session in that project to use FinishUP there. |
