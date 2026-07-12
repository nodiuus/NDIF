Project: dbi_agent

Purpose
- In-target agent DLL for controller/agent workflows.
- Current MVP behavior:
  - connects to named pipe `\\.\pipe\dbi_agent_<pid>`
  - sends hello/version handshake
  - accepts one start command and replies with ACK

Build output
- `<Platform>\<Configuration>\dbi_agent.dll`
- Build the agent for the same architecture as the host and target process.

Controller command
- `DBI.exe -i <pid>`
- `DBI.exe -i <pid> <section_name>`
- `DBI.exe -i <pid> <module_name> <section_name>`

TODO:
  - Add websocket support
