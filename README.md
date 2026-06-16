# NDIF

NDIF stands for "Nisan's Dynamic Instrumentation Framework" (yes I skipped the "binary" part for a cooler name). 

This repository is a public alpha for Windows x64 dynamic binary instrumentation experiments.

The alpha is intentionally small: it ships the DBI core/CLI, one sample plugin, and the minimal in-target agent DLL. Larger research projects and detector zoos are kept out of the public solution for now.

I've made a lot of plugins / tools using this framework, I may release them later for public use.

## Public Alpha Scope

Included in `DBI.slnx`:

- `DBI/DBI.vcxproj`: CLI host and embeddable DBI framework.
- `DBI/plugins/framework_showcase/framework_showcase.vcxproj`: sample plugin that exercises lifecycle hooks, command dispatch, instrumentation callbacks, and the host patch API.
- `dbi_agent/dbi_agent.vcxproj`: in-target agent DLL used by injection/agent workflow experiments.

Not included in the public alpha solution:

- local detector plugins, hook/anti-debug zoos, sandbox/protector experiments, GUI experiments, and test-only projects.
- ignored local folders listed in `.gitignore`.

## Requirements

- Windows 10/11 x64
- Visual Studio 2026 or newer with C++ desktop workload
- vcpkg manifest integration
- x64 build configuration

Dependencies are declared in `vcpkg.json`:

- `imgui` with Win32/DX11 bindings
- `lief`
- `nlohmann-json`
- `zydis`

## Build

From a Developer PowerShell:

```powershell
msbuild DBI.slnx /p:Configuration=Debug /p:Platform=x64 /m
```

If `msbuild` is not on PATH, launch the command from a Visual Studio developer shell or use the full MSBuild path from `vswhere`.

Expected outputs:

- `DBI\x64\Debug\DBI.exe`
- `x64\Debug\plugins\framework_showcase.dll`
- `x64\Debug\dbi_agent.dll`

## CLI Usage

Basic forms:

```powershell
DBI.exe <target.exe> [args...]
DBI.exe --instruction-callback-demo
DBI.exe --dispatcher-callback-demo
DBI.exe --indirect-redirect-demo
DBI.exe --translated-cache-demo
DBI.exe -l
DBI.exe -p framework_showcase -c showcase.help
DBI.exe -p framework_showcase -c showcase.ping
DBI.exe -p framework_showcase -c showcase.stats
DBI.exe -p framework_showcase -c showcase.patch_demo
```

Plugin loading:

- `-P <dir>` / `--plugins-dir <dir>`: set plugin search directory.
- `-p <path-or-name>` / `--plugin <path-or-name>`: load a plugin by path or short name.
- `-N` / `--no-plugins`: disable plugin auto-loading.
- `-c <command> [args...]` / `--cmd <command> [args...]`: dispatch a plugin command.

Agent workflow:

```powershell
DBI.exe -i <pid>
DBI.exe -i <pid> <section_name>
DBI.exe -i <pid> <module_name> <section_name>
```

The current agent is an MVP handshake path: it connects to `\\.\pipe\dbi_agent_<pid>`, sends a hello/version message, accepts one start command, and replies with ACK.

## Core API Shape

Primary public C++ surfaces live under `DBI/`:

- `dbi_framework.*`: high-level framework wrapper.
- `basic_block_code_cache.h`: translated basic-block cache prototype for cache-owned function execution.
- `dynamic_binary_instrumentor.*`: in-process instrumentation coordinator.
- `dispatcher_code_cache_instrumentor.h`: non-mutating hardware-breakpoint redirect backend. Registered addresses execute through generated cache blocks while the original bytes stay readable and intact.
- `external_process_instrumentor.*`: debugger-driven external process instrumentation.
- `live_patch_framework.*`: host-side patch helper exposed to plugins.
- `plugin_api.h`: stable C ABI for plugins.
- `plugin_manager.*`: plugin loading and event dispatch.
- `dbi_host.*`: host wrapper around plugin manager and default plugin discovery.

The default in-process instruction callback engine is now the translated basic-block cache. Callers can explicitly enter through `translated_function<T>()` / `translated_entry()`, redirect an existing mutable code-pointer slot, or perform a DBT-style thread handoff with `translate_context()` / `handoff_thread()`. The translated-cache backend does not patch call-site bytes and does not install a VEH entry trap.

For call sites that already use a mutable code-pointer boundary, callers can register a pointer slot with `redirect_indirect_call_target()` / `redirect_indirect_function<T>()`. When callbacks are enabled, NDIF translates the slot's current destination and replaces only the pointer slot with the cache entry; the caller's instruction bytes are left untouched. `restore_indirect_redirect()` or `disable_instruction_callbacks()` restores the original slot value.

The legacy dispatcher backend remains available through `dbi_framework_options::instruction_backend = instruction_callback_backend::dispatcher_code_cache` and through `DBI.exe --dispatcher-callback-demo`. It uses hardware execute breakpoints as entry traps, catches matching execution with a VEH, and redirects matching instruction pointers to a generated code-cache block while leaving original bytes intact.

## Sample Plugin

`framework_showcase` exports:

```cpp
extern "C" __declspec(dllexport) int dbi_call dbi_plugin_init(dbi_plugin_api* out);
```

Commands:

- `showcase.help`
- `showcase.ping`
- `showcase.stats`
- `showcase.patch_demo`

## Known Limitations

- Public alpha, not a stable API promise.
- Windows x64 is the real target. x86 project configurations may exist but are not the alpha support target.
- The default translated-cache backend observes explicit translated entrypoints, redirected pointer slots, and threads handed off by context rewrite. It is not full-process transparent DBT for arbitrary already-running original code.
- Indirect pointer-slot redirects require an existing mutable function pointer, callback slot, vtable/IAT-like entry, or equivalent boundary. They do not redirect hardcoded direct calls by themselves.
- The legacy hardware-breakpoint dispatcher instruments up to four explicit addresses per thread, not full process-wide basic-block translation.
- The translated basic-block cache is an early prototype. It supports ordinary instructions, returns, and direct conditional/unconditional branches, including simple backward branches; unsupported indirect control flow can still leave the cache.
- Callback `CONTEXT` includes x64 integer registers and flags. Edits to general-purpose registers and flags are applied before relocated bytes resume; edits to `RIP`/`RSP` are not applied yet.
- Some injection/agent paths are experimental and should be treated as lab tooling.
- Build/test coverage is manual right now; CI is not wired yet.
