from saq.database.model import AuthGroupPermission, AuthUserPermission, AuthGroupUser
from saq.database.pool import get_db
from saq.permissions.constants import ALLOW, DENY
from fnmatch import fnmatchcase

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _evaluate_permission(user_perms, group_perms, major: str, minor: str) -> bool:
    """Apply fnmatch over the fetched (major, minor, effect) rows. DENY overrides ALLOW."""
    # fnmatch: stored patterns (major/minor) against requested values
    def matches(pattern_major: str, pattern_minor: str) -> bool:
        return fnmatchcase(major, pattern_major) and fnmatchcase(minor, pattern_minor)

    matched_effects = [
        effect for (p_major, p_minor, effect) in user_perms if matches(p_major, p_minor)
    ] + [
        effect for (p_major, p_minor, effect) in group_perms if matches(p_major, p_minor)
    ]

    if not matched_effects:
        return False

    if DENY in matched_effects:
        return False

    return ALLOW in matched_effects


def user_has_permission(
    user_id: int,
    major: str,
    minor: str,
) -> bool:
    """Check if a user has a specific permission. DENY overrides ALLOW."""
    session = get_db()

    # Fetch all user permissions and filter via fnmatch (pattern in DB, value is requested)
    user_perms = (
        session.query(
            AuthUserPermission.major,
            AuthUserPermission.minor,
            AuthUserPermission.effect,
        )
        .filter(AuthUserPermission.user_id == user_id)
        .all()
    )

    # Group permissions
    group_ids = [
        r.group_id
        for r in session.query(AuthGroupUser.group_id).filter(AuthGroupUser.user_id == user_id).all()
    ]

    group_perms = []
    if group_ids:
        group_perms = (
            session.query(
                AuthGroupPermission.major,
                AuthGroupPermission.minor,
                AuthGroupPermission.effect,
            )
            .filter(AuthGroupPermission.group_id.in_(group_ids))
            .all()
        )

    return _evaluate_permission(user_perms, group_perms, major, minor)


async def user_has_permission_async(
    session: AsyncSession,
    user_id: int,
    major: str,
    minor: str,
) -> bool:
    """Async equivalent of user_has_permission() using an AsyncSession."""
    # Fetch all user permissions and filter via fnmatch (pattern in DB, value is requested)
    user_perms = (
        await session.execute(
            select(
                AuthUserPermission.major,
                AuthUserPermission.minor,
                AuthUserPermission.effect,
            ).where(AuthUserPermission.user_id == user_id)
        )
    ).all()

    # Group permissions
    group_ids = [
        r.group_id
        for r in (
            await session.execute(
                select(AuthGroupUser.group_id).where(AuthGroupUser.user_id == user_id)
            )
        ).all()
    ]

    group_perms = []
    if group_ids:
        group_perms = (
            await session.execute(
                select(
                    AuthGroupPermission.major,
                    AuthGroupPermission.minor,
                    AuthGroupPermission.effect,
                ).where(AuthGroupPermission.group_id.in_(group_ids))
            )
        ).all()

    return _evaluate_permission(user_perms, group_perms, major, minor)
