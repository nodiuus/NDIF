# Contributing

NDIF is currently a public alpha. Contributions are welcome, but keep changes small and easy to review.

## Development Setup

Use Windows with Visual Studio C++ tooling and vcpkg manifest mode.

Build:

```powershell
msbuild DBI.slnx /p:Configuration=Debug /p:Platform=x64 /m
msbuild DBI.slnx /p:Configuration=Debug /p:Platform=Win32 /m
```

## Pull Requests

Please include:

- a short description of the behavior change
- build/test commands you ran
- any known limitations
- screenshots only when changing UI behavior

## Code Style

- Prefer existing local patterns over broad rewrites.
- Keep the public alpha solution focused on checked-in projects.
- Do not add local/private experiments to `DBI.slnx`.
- Keep plugin ABI changes explicit and documented.

## Security

Do not submit code or examples intended for unauthorized access, stealth, or abuse. See `SECURITY.md` for vulnerability reporting.
