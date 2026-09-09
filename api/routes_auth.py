"""
api/routes_auth.py — Authentication endpoints (login, register).
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.models import User
from db.schemas import LoginRequest, TokenResponse, UserOut
from api.auth import verify_password, hash_password, create_access_token
from api.dependencies import get_db, get_current_user

logger = logging.getLogger("ids.api.auth")
router = APIRouter(prefix="/api", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Authenticate a user and return a JWT access token.

    The token should be included in subsequent requests as:
        Authorization: Bearer <token>
    """
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning("Failed login attempt for user: %s", body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(data={"sub": user.username})
    logger.info("User '%s' logged in successfully", user.username)

    return TokenResponse(access_token=token)


@router.post("/register", response_model=UserOut)
async def register(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a new dashboard user (admin-only).

    The first user is created automatically on startup.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can register new users",
        )

    # Check for duplicate username
    existing = await db.execute(
        select(User).where(User.username == body.username)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User '{body.username}' already exists",
        )

    user = User(
        username=body.username,
        hashed_password=hash_password(body.password),
        is_admin=False,
    )
    db.add(user)
    await db.flush()

    logger.info("New user registered: %s (by admin %s)", body.username, current_user.username)
    return user
