from typing import AsyncGenerator, Optional
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.base import get_session
from app.db.models import User, APIKey
from sqlalchemy import select
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)

# Initialize OAuth2 scheme with token URL
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=True
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session"""
    from app.db.base import async_session
    async with async_session() as session:
        yield session

async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get the current authenticated user from token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Import jwt functions here to avoid circular imports
        from jose import jwt, JWTError
        
        # Decode token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        email: Optional[str] = payload.get("sub")
        if email is None:
            logger.warning("Token payload missing 'sub' claim")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT error: {str(e)}")
        raise credentials_exception
    except ImportError as e:
        logger.error(f"ImportError in get_current_user: {str(e)}")
        raise credentials_exception
    
    try:
        # Find user in database
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if user is None:
            logger.warning(f"User not found: {email}")
            raise credentials_exception
            
        if not user.is_active:
            logger.warning(f"Inactive user attempted access: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user"
            )
            
        return user
    except Exception as e:
        logger.error(f"Database error in get_current_user: {str(e)}")
        raise credentials_exception


async def validate_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> Optional[APIKey]:
    """
    Validate API key from X-API-Key header.
    Returns the APIKey object if valid, None if no key provided.
    Raises 401 if key is invalid/expired/revoked.
    """
    if not x_api_key:
        return None
    
    # Hash the provided key to compare with stored hash
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        logger.warning(f"Invalid API key attempted: {x_api_key[:12]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    if not api_key.is_active:
        logger.warning(f"Revoked API key attempted: {api_key.name}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked"
        )
    
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        logger.warning(f"Expired API key attempted: {api_key.name}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    # Update last used timestamp
    api_key.last_used = datetime.utcnow()
    await db.commit()
    
    logger.debug(f"API key validated: {api_key.name}")
    return api_key


async def require_api_key(
    api_key: Optional[APIKey] = Depends(validate_api_key)
) -> APIKey:
    """Require a valid API key - raises 401 if not provided."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Get one from Dashboard > Settings > API Keys"
        )
    return api_key
