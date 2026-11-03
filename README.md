# getkeys

A [maubot](https://github.com/maubot/maubot) plugin that lets users request the bot's
end-to-end encryption keys for a room, so they can read that room's encrypted history
without having to obtain keys from other members.

> [!WARNING]
Sharing encryption keys is inherently insescure. Use this plugin at your own risk. Even if you trust all people in an
encrypted room, their account may be on a compromised homeserver, whose admin could potentially use their
account to invite unintended room members who would then be able to read encrypted room history with this plugin.
By using this plugin you are knowingly poking holes in security frameworks.

When a permitted user sends `!getkeys` in an encrypted room, the bot:

1. Collects every Megolm session key it holds for that room.
2. Writes them to a standard encrypted key export file (the same format as Element's
   "Export E2E room keys"), protected by a freshly generated random password.
3. Sends the file and then the password, as two separate messages, in an **encrypted
   1:1 DM** with the user. If no such DM exists, it creates one and sends the keys once
   the user accepts the invite.

The user can then import the file in any client that supports it (Element:
*Settings → Security & Privacy → Cryptography → Import E2E room keys*).

## Limitations

The bot can only export keys it actually has: messages sent while it was in the room and
the room was encrypted. History from before the bot joined cannot be unlocked this way.

## Requirements

- The maubot client must have encryption enabled (a device ID with crypto set up).
- The bot must be in the rooms you want keys for.

## Commands

| Command | Who | Description |
| --- | --- | --- |
| `!getkeys` | permitted users | Send this room's keys to you in a DM |
| `!getkeys status` | anyone | Show whether export is enabled here (and the key count, if you're permitted) |
| `!getkeys block` | admins | Disable key export in this room |
| `!getkeys unblock` | admins | Re-enable key export in this room (rooms blocked in the config stay blocked) |

## Configuration

See [`base-config.yaml`](base-config.yaml). A user may export keys if they are joined to the
room, the room isn't blocked, and at least one of these is true:

- they're listed in `admins`,
- they're listed in `permissions.allowed_users`, or
- `permissions.min_power_level` is set and their power level in the room is at least that value.

Rooms listed in `blocked_rooms` always refuse key export. Admins can also block rooms at runtime
with `!getkeys block`; those blocks are stored in the plugin database.

## Security notes

- **This deliberately bypasses Matrix's "new members can't read old encrypted history" property.**
  The export contains *every* key the bot holds for the room: messages from before the requester
  joined, from periods when they had left, and from senders who chose not to share keys with them.
  Pick `permissions` with that in mind. `min_power_level: 0` lets any newcomer read the full history
  the bot can see, and it can only be undone by blocking the room.
- Key files are only ever sent to a DM that is end-to-end encrypted, invite-only, and contains
  exactly the bot and the requesting user. This is checked again right before sending. Otherwise
  the bot refuses to send.
- The DM is encrypted to all of the requester's devices, including unverified ones (mautrix's
  default). If someone has stolen their access token and added a device, that device gets the keys too.
- The file and the password are separate messages to make copying easy. They travel in the same
  encrypted DM, so splitting them adds no real security.
- Nothing is cached: the export and password are generated at delivery time and never
  stored by the plugin.
- Every export is logged with the requester, room and number of keys.
- Anyone who has the file and password can read the room history the bot could read. Tell users to
  delete the DM messages once they've imported the keys.

## Development

```sh
python3 tests/test_export.py
```

The tests need `pycryptodome` (and optionally `python-olm`), both of which ship with maubot.
To build the plugin: `mbc build` (or zip `maubot.yaml`, `base-config.yaml` and `getkeys/` into
a `.mbp` file).
