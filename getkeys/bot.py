import asyncio
import html
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type

from attr import dataclass
from maubot import MessageEvent, Plugin
from maubot.handlers import command, event
from mautrix.crypto.attachments import encrypt_attachment
from mautrix.errors import GroupSessionWithheldError, MatrixRequestError, MNotFound
from mautrix.types import (
    EventType,
    FileInfo,
    Format,
    JoinRule,
    MediaMessageEventContent,
    Membership,
    MessageType,
    RoomCreatePreset,
    RoomID,
    StateEvent,
    TextMessageEventContent,
    UserID,
)
from mautrix.util.async_db import UpgradeTable
from mautrix.util.config import BaseProxyConfig

from .config import Config
from .db import DB, upgrade_table
from .export import encrypt_key_export, generate_passphrase

MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"


@dataclass
class PendingDelivery:
    user_id: UserID
    source_room: RoomID
    dm_room: RoomID
    expires_at: float


class GetKeysBot(Plugin):
    config: Config
    db: DB
    # (user, source room) -> pending delivery waiting for the user to join a new DM.
    # Only room IDs are kept here; the export itself is generated at delivery time.
    pending: Dict[Tuple[UserID, RoomID], PendingDelivery]
    # (user, source room) -> unix timestamp of the last accepted request
    last_request: Dict[Tuple[UserID, RoomID], float]

    async def start(self) -> None:
        await super().start()
        self.config.load_and_update()
        self.db = DB(self.database)
        self.pending = {}
        self.last_request = {}
        # Serializes DM lookup/creation and m.direct read-modify-writes.
        self.dm_lock = asyncio.Lock()
        if not self.client.crypto:
            self.log.warning(
                "This client does not have encryption enabled; !getkeys will not work"
            )

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    @classmethod
    def get_db_upgrade_table(cls) -> UpgradeTable:
        return upgrade_table

    async def on_external_config_update(self) -> None:
        self.config.load_and_update()

    # region Permissions

    def is_admin(self, user_id: UserID) -> bool:
        return user_id in self.config["admins"]

    async def is_blocked(self, room_id: RoomID) -> bool:
        return room_id in self.config["blocked_rooms"] or await self.db.is_blocked(room_id)

    async def is_joined(self, room_id: RoomID, user_id: UserID) -> bool:
        return await self.get_membership(room_id, user_id) == Membership.JOIN

    async def get_membership(self, room_id: RoomID, user_id: UserID) -> Optional[Membership]:
        try:
            member = await self.client.get_state_event(room_id, EventType.ROOM_MEMBER, user_id)
        except MatrixRequestError:
            return None
        return member.membership

    async def may_export(self, room_id: RoomID, user_id: UserID) -> bool:
        if self.is_admin(user_id) or user_id in self.config["permissions.allowed_users"]:
            return True
        min_level = self.config["permissions.min_power_level"]
        if min_level is None:
            return False
        try:
            levels = await self.client.get_state_event(room_id, EventType.ROOM_POWER_LEVELS)
        except MatrixRequestError:
            return False
        return levels.get_user_level(user_id) >= int(min_level)

    # endregion
    # region Commands

    @command.new(
        # maubot lowercases the typed command before matching
        name=lambda self: self.config["command_prefix"].lower(),
        help="Get this room's encryption keys sent to you in a DM",
        require_subcommand=False,
    )
    async def getkeys(self, evt: MessageEvent) -> None:
        room_id, user_id = evt.room_id, evt.sender
        if not self.client.crypto:
            await evt.reply("I don't have encryption enabled, so I have no keys to export.")
            return
        if await self.is_blocked(room_id):
            await evt.reply("Key export is disabled for this room.")
            return
        if not await self.may_export(room_id, user_id):
            await evt.reply("You don't have permission to request keys for this room.")
            return
        if not await self.is_joined(room_id, user_id):
            await evt.reply("You must be joined to this room to request its keys.")
            return

        now = time.time()
        cooldown = int(self.config["cooldown_seconds"])
        last = self.last_request.get((user_id, room_id))
        if last is not None and now - last < cooldown:
            await evt.reply(
                f"Please wait {int(cooldown - (now - last))} seconds before requesting "
                "this room's keys again."
            )
            return

        self.log.info(f"{user_id} requested a key export for {room_id}")
        try:
            async with self.dm_lock:
                dm_room = await self.find_dm(user_id)
                if dm_room:
                    await evt.reply("I'm sending this room's keys to you in a DM.")
                    if await self.deliver(user_id, room_id, dm_room):
                        self.last_request[(user_id, room_id)] = now
                    return

                self.expire_pending()
                timeout = int(self.config["dm_join_timeout"])
                dm_room = await self.find_pending_dm(user_id)
                created = dm_room is None
                if created:
                    dm_room = await self.client.create_room(
                        preset=RoomCreatePreset.TRUSTED_PRIVATE,
                        is_direct=True,
                        invitees=[user_id],
                        initial_state=[
                            {
                                "type": EventType.ROOM_ENCRYPTION.serialize(),
                                "state_key": "",
                                "content": {"algorithm": MEGOLM_ALGORITHM},
                            }
                        ],
                    )
                    self.log.info(f"Created DM {dm_room} with {user_id}")
                # Register before anything else is awaited, so a fast join isn't missed.
                self.pending[(user_id, room_id)] = PendingDelivery(
                    user_id=user_id, source_room=room_id, dm_room=dm_room, expires_at=now + timeout
                )
                self.last_request[(user_id, room_id)] = now
                if created:
                    await self.add_direct_room(user_id, dm_room)
        except Exception:
            self.log.exception(f"Failed to set up a DM with {user_id}")
            await evt.reply("Something went wrong while creating a DM with you.")
            return

        await evt.reply(
            "I've invited you to an encrypted DM. Accept the invite within "
            f"{timeout // 60} minutes and I'll send this room's keys there."
        )
        # The user may have joined while the m.direct update was in flight.
        if await self.is_joined(dm_room, user_id) and (user_id, room_id) in self.pending:
            del self.pending[(user_id, room_id)]
            await self.deliver(user_id, room_id, dm_room)

    @getkeys.subcommand("block", help="Disable key export in this room (admins only)")
    async def block(self, evt: MessageEvent) -> None:
        if not self.is_admin(evt.sender):
            await evt.reply("Only bot admins can block rooms.")
            return
        if await self.db.block(evt.room_id, evt.sender):
            self.log.info(f"{evt.sender} blocked key export in {evt.room_id}")
            await evt.reply("Key export is now disabled for this room.")
        else:
            await evt.reply("Key export was already disabled for this room.")

    @getkeys.subcommand("unblock", help="Re-enable key export in this room (admins only)")
    async def unblock(self, evt: MessageEvent) -> None:
        if not self.is_admin(evt.sender):
            await evt.reply("Only bot admins can unblock rooms.")
            return
        removed = await self.db.unblock(evt.room_id)
        if evt.room_id in self.config["blocked_rooms"]:
            await evt.reply(
                "This room is blocked in the plugin config. Remove it from `blocked_rooms` "
                "in the instance config to re-enable key export."
            )
            return
        if removed:
            self.log.info(f"{evt.sender} unblocked key export in {evt.room_id}")
            await evt.reply("Key export is now enabled for this room.")
        else:
            await evt.reply("Key export wasn't disabled for this room.")

    @getkeys.subcommand("status", help="Show whether key export is available in this room")
    async def status(self, evt: MessageEvent) -> None:
        if evt.room_id in self.config["blocked_rooms"]:
            state = "disabled (by plugin config)"
        elif blocked_by := await self.db.get_blocked_by(evt.room_id):
            state = f"disabled (blocked by {blocked_by})"
        else:
            state = "enabled"
        lines = [f"Key export in this room is **{state}**."]
        if self.client.crypto and await self.may_export(evt.room_id, evt.sender):
            count = len(await self.list_session_ids(evt.room_id))
            lines.append(f"I have {count} session key(s) for this room.")
        await evt.reply("\n\n".join(lines))

    # endregion
    # region DM handling

    async def is_private_encrypted_dm(self, room_id: RoomID, user_id: UserID) -> bool:
        """Check that only the bot and the user are in the room, both joined, and it's encrypted."""
        try:
            members = await self.client.get_members(room_id)
        except MatrixRequestError:
            return False
        active = {
            evt.state_key: evt.content.membership
            for evt in members
            if evt.content.membership in (Membership.JOIN, Membership.INVITE)
        }
        if active != {self.client.mxid: Membership.JOIN, user_id: Membership.JOIN}:
            return False
        try:
            join_rules = await self.client.get_state_event(room_id, EventType.ROOM_JOIN_RULES)
            if join_rules.join_rule != JoinRule.INVITE:
                return False
            encryption = await self.client.get_state_event(room_id, EventType.ROOM_ENCRYPTION)
        except MatrixRequestError:
            return False
        if encryption.algorithm.value != MEGOLM_ALGORITHM:
            return False
        # The client only encrypts outgoing messages if its state store agrees.
        return bool(await self.client.state_store.is_encrypted(room_id))

    async def get_direct_rooms(self) -> Dict[str, List[str]]:
        try:
            return await self.client.get_account_data(EventType.DIRECT) or {}
        except MNotFound:
            return {}

    async def find_dm(self, user_id: UserID) -> Optional[RoomID]:
        for room_id in (await self.get_direct_rooms()).get(user_id, []):
            if await self.is_private_encrypted_dm(RoomID(room_id), user_id):
                return RoomID(room_id)
        return None

    async def add_direct_room(self, user_id: UserID, room_id: RoomID) -> None:
        direct = await self.get_direct_rooms()
        direct.setdefault(user_id, []).append(room_id)
        await self.client.set_account_data(EventType.DIRECT, direct)

    async def find_pending_dm(self, user_id: UserID) -> Optional[RoomID]:
        """Reuse a DM we're already waiting on, as long as the user can still accept it."""
        for pending in list(self.pending.values()):
            if pending.user_id != user_id:
                continue
            if await self.get_membership(pending.dm_room, user_id) == Membership.INVITE:
                return pending.dm_room
            self.drop_pending(pending.dm_room, user_id)
        return None

    def drop_pending(self, dm_room: RoomID, user_id: UserID) -> None:
        for key, pending in list(self.pending.items()):
            if pending.dm_room == dm_room and pending.user_id == user_id:
                del self.pending[key]

    def expire_pending(self) -> None:
        now = time.time()
        for key, pending in list(self.pending.items()):
            if pending.expires_at < now:
                self.log.info(
                    f"Delivery of {pending.source_room} keys to {pending.user_id} expired"
                )
                del self.pending[key]

    @event.on(EventType.ROOM_MEMBER)
    async def on_member(self, evt: StateEvent) -> None:
        if not self.pending:
            return
        if evt.content.membership in (Membership.LEAVE, Membership.BAN):
            # Declined the invite or left: the DM can't be used anymore.
            self.drop_pending(evt.room_id, UserID(evt.state_key))
            return
        if evt.content.membership != Membership.JOIN:
            return
        self.expire_pending()
        ready = [
            key
            for key, p in self.pending.items()
            if p.dm_room == evt.room_id and p.user_id == evt.state_key
        ]
        for key in ready:
            pending = self.pending.pop(key)
            await self.deliver(pending.user_id, pending.source_room, pending.dm_room)

    # endregion
    # region Export

    async def list_session_ids(self, room_id: RoomID) -> List[str]:
        store = self.client.crypto.crypto_store
        q = (
            "SELECT session_id FROM crypto_megolm_inbound_session "
            "WHERE room_id=$1 AND account_id=$2 AND session IS NOT NULL"
        )
        rows = await store.db.fetch(q, room_id, store.account_id)
        return [row["session_id"] for row in rows]

    async def collect_sessions(self, room_id: RoomID) -> List[Dict[str, Any]]:
        store = self.client.crypto.crypto_store
        sessions = []
        for session_id in await self.list_session_ids(room_id):
            try:
                session = await store.get_group_session(room_id, session_id)
            except GroupSessionWithheldError:
                continue
            if session is None or not session.signing_key:
                continue
            sessions.append(
                {
                    "algorithm": MEGOLM_ALGORITHM,
                    "forwarding_curve25519_key_chain": session.forwarding_chain,
                    "room_id": room_id,
                    "sender_key": session.sender_key,
                    "sender_claimed_keys": {"ed25519": session.signing_key},
                    "session_id": session.id,
                    "session_key": session.export_session(session.first_known_index),
                }
            )
        return sessions

    async def export_filename(self, room_id: RoomID) -> str:
        try:
            name = (await self.client.get_state_event(room_id, EventType.ROOM_NAME)).name
        except MNotFound:
            name = ""
        slug = re.sub(r"[^A-Za-z0-9]+", "-", name or room_id).strip("-")[:48] or "room"
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"room-keys-{slug}-{date}.txt"

    async def deliver(self, user_id: UserID, source_room: RoomID, dm_room: RoomID) -> bool:
        """Export the source room's keys and send them to the DM. Returns True on success."""
        # Re-check everything at delivery time, since the user may have waited to join the DM.
        if await self.is_blocked(source_room):
            await self.client.send_notice(dm_room, "Key export has been disabled for that room.")
            return False
        if not await self.may_export(source_room, user_id) or not await self.is_joined(
            source_room, user_id
        ):
            await self.client.send_notice(
                dm_room, "You're no longer allowed to request keys for that room."
            )
            return False

        try:
            sessions = await self.collect_sessions(source_room)
            if not sessions:
                await self.client.send_notice(dm_room, "I don't have any keys for that room.")
                return False
            passphrase = generate_passphrase()
            data = await asyncio.get_running_loop().run_in_executor(
                None,
                encrypt_key_export,
                sessions,
                passphrase,
                int(self.config["pbkdf2_rounds"]),
            )
            filename = await self.export_filename(source_room)
            ciphertext, file = encrypt_attachment(data)
            # Validate as late as possible: the megolm session is shared with whoever is in
            # the room when the message is encrypted, not when we first checked.
            if not await self.is_private_encrypted_dm(dm_room, user_id):
                self.log.warning(
                    f"Refusing to send {source_room} keys to {user_id}: {dm_room} is not a "
                    "private, invite-only, encrypted DM"
                )
                return False
            file.url = await self.client.upload_media(
                ciphertext, mime_type="application/octet-stream", filename=filename
            )
            await self.client.send_message(
                dm_room,
                MediaMessageEventContent(
                    msgtype=MessageType.FILE,
                    body=filename,
                    filename=filename,
                    file=file,
                    info=FileInfo(mimetype="text/plain", size=len(data)),
                ),
            )
            await self.client.send_message(
                dm_room,
                TextMessageEventContent(
                    msgtype=MessageType.TEXT,
                    body=passphrase,
                    format=Format.HTML,
                    formatted_body=f"<code>{html.escape(passphrase)}</code>",
                ),
            )
            await self.client.send_notice(
                dm_room,
                f"That's the password for the {len(sessions)} key(s) in the file above, "
                f"for {source_room}. To use it, open your client's security settings, choose "
                "\"Import E2E room keys\", and select the file. Delete these messages "
                "once you've imported it.",
            )
            self.log.info(f"Sent {len(sessions)} keys for {source_room} to {user_id} in {dm_room}")
            return True
        except Exception:
            self.log.exception(f"Failed to export keys for {source_room} to {user_id}")
            await self.client.send_notice(dm_room, "Something went wrong exporting the keys.")
            return False

    # endregion
