Plugin: framework_showcase

Purpose
- Minimal plugin that demonstrates framework/plugin capabilities:
  - lifecycle hooks (`on_load`, `on_unload`, `on_process_start`, `on_process_exit`)
  - instrumentation callbacks (`on_instruction_hit`, `on_branch_hit`)
  - command dispatch (`on_command`)
  - host patch service (`apply_patch_bytes`, `remove_patch`)

Commands
- `showcase.help`
- `showcase.ping`
- `showcase.stats`
- `showcase.patch_demo`

Example usage
- `DBI.exe -p framework_showcase -c showcase.help`
- `DBI.exe -p framework_showcase -c showcase.patch_demo`

Output
- Logs to host/plugin log stream with hook counts and patch-demo status.
