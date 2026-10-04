# Minecraft workload fixtures

These fixtures exercise the supported workload inputs without depending on mutable remote files during tests.

| Fixture | Purpose | Upstream reference |
| --- | --- | --- |
| `paper-egg.json` | Minimal `PTDL_v2` Paper planning fixture | [Pterodactyl Paper Egg](https://github.com/pterodactyl/game-eggs/blob/main/minecraft/java/paper/egg-paper.json) |
| `compose.yaml` | Paper server through the `itzg/minecraft-server` image | [itzg Compose example](https://github.com/itzg/docker-minecraft-server/blob/master/examples/docker-compose.yml) |
| `Dockerfile` | Dockerfile planning and build-policy fixture | [itzg image documentation](https://github.com/itzg/docker-minecraft-server) |
| `portainer-template.json` | Portainer v2 type-1 import normalized by the portal into OCI input | [Portainer App Template format](https://docs.portainer.io/advanced/app-templates/format) |

The Portainer fixture is derived from the documented v2 format. The current official Portainer template catalog has no Minecraft entry. Portainer templates are portal-side import inputs and are never executed directly by the agent.
