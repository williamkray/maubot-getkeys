import time
from typing import Optional

from mautrix.types import RoomID, UserID
from mautrix.util.async_db import Connection, Database, UpgradeTable

upgrade_table = UpgradeTable()


@upgrade_table.register(description="Initial revision")
async def upgrade_v1(conn: Connection) -> None:
    await conn.execute(
        """CREATE TABLE blocked_rooms (
            room_id    TEXT PRIMARY KEY,
            blocked_by TEXT NOT NULL,
            blocked_at BIGINT NOT NULL
        )"""
    )


class DB:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def is_blocked(self, room_id: RoomID) -> bool:
        q = "SELECT 1 FROM blocked_rooms WHERE room_id=$1"
        return await self.db.fetchval(q, room_id) is not None

    async def get_blocked_by(self, room_id: RoomID) -> Optional[UserID]:
        q = "SELECT blocked_by FROM blocked_rooms WHERE room_id=$1"
        return await self.db.fetchval(q, room_id)

    async def block(self, room_id: RoomID, user_id: UserID) -> bool:
        if await self.is_blocked(room_id):
            return False
        q = "INSERT INTO blocked_rooms (room_id, blocked_by, blocked_at) VALUES ($1, $2, $3)"
        await self.db.execute(q, room_id, user_id, int(time.time() * 1000))
        return True

    async def unblock(self, room_id: RoomID) -> bool:
        if not await self.is_blocked(room_id):
            return False
        await self.db.execute("DELETE FROM blocked_rooms WHERE room_id=$1", room_id)
        return True
