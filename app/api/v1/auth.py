from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Dict
import httpx
import secrets
from urllib.parse import urlencode

from ...core.database import get_db, get_redis
from ...core.config import settings
from ...core.security import generate_oauth_state, verify_oauth_state
from ...api.deps import (
    get_current_user, rate_limit_check, check_account_lockout,
    get_current_user_token
)
from ...services.auth_service import AuthService
from ...schemas.auth import (
    UserLogin, UserRegister, TokenResponse, UserResponse,
    RefreshTokenRequest, PasswordReset, PasswordResetConfirm,
    OAuthCallback, ChangePassword
)
from ...models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserRegister,
    db: Session = Depends(get_db),
    _: None = Depends(rate_limit_check)
):
    """Register a new user."""
    auth_service = AuthService(db)
    user = auth_service.register_user(user_data)
    
    # TODO: Send verification email
    
    return UserResponse.from_orm(user)

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    login_data: UserLogin,
    db: Session = Depends(get_db),
):
    """Authenticate user and return access tokens."""
    # Pass both request and login_data to make it work in both scenarios
    auth_service = AuthService(db)
    return auth_service.authenticate_user(login_data)

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token."""
    auth_service = AuthService(db)
    return auth_service.refresh_access_token(refresh_data.refresh_token)

@router.post("/logout")
async def logout(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Logout user by revoking refresh token."""
    auth_service = AuthService(db)
    success = auth_service.logout_user(refresh_data.refresh_token)
    
    return {"message": "Successfully logged out" if success else "Logout completed"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return UserResponse.from_orm(current_user)

@router.post("/change-password")
async def change_password(
    password_data: ChangePassword,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password."""
    from ...core.security import verify_password, get_password_hash
    
    # Verify current password
    if not verify_password(password_data.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    current_user.password_hash = get_password_hash(password_data.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}

@router.post("/forgot-password")
async def forgot_password(
    reset_data: PasswordReset,
    db: Session = Depends(get_db),
    _: None = Depends(rate_limit_check)
):
    """Request password reset."""
    auth_service = AuthService(db)
    auth_service.request_password_reset(reset_data.email)
    
    return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Reset password using reset token."""
    auth_service = AuthService(db)
    auth_service.reset_password(reset_data)
    
    return {"message": "Password reset successfully"}

# OAuth 2.0 routes
@router.get("/oauth/{provider}/login")
async def oauth_login(
    provider: str,
    request: Request,
    redis_client = Depends(get_redis)
):
    """Initiate OAuth login flow."""
    if provider not in ["google"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported OAuth provider"
        )
    
    # Generate state parameter for CSRF protection
    state = generate_oauth_state()
    
    # Store state in Redis with expiration
    redis_client.setex(f"oauth_state:{state}", 600, provider)  # 10 minutes
    
    if provider == "google":
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.OAUTH_REDIRECT_URI,
            "scope": "openid email profile",
            "response_type": "code",
            "state": state,
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}"
        return {"auth_url": auth_url}

@router.post("/oauth/callback", response_model=TokenResponse)
async def oauth_callback(
    callback_data: OAuthCallback,
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis)
):
    """Handle OAuth callback."""
    # Verify state parameter
    stored_provider = redis_client.get(f"oauth_state:{callback_data.state}")
    if not stored_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter"
        )
    
    # Delete used state
    redis_client.delete(f"oauth_state:{callback_data.state}")
    
    if stored_provider == "google":
        return await _handle_google_callback(callback_data.code, db)
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported OAuth provider"
    )

async def _handle_google_callback(code: str, db: Session) -> TokenResponse:
    """Handle Google OAuth callback."""
    # Exchange code for access token
    token_data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.OAUTH_REDIRECT_URI,
    }
    
    async with httpx.AsyncClient() as client:
        # Get access token
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data=token_data
        )
        
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange code for token"
            )
        
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        
        # Get user info
        user_response = await client.get(
            f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        )
        
        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get user information"
            )
        
        user_info = user_response.json()
    
    # Create OAuth user info
    from ...schemas.auth import OAuthUserInfo
    oauth_user = OAuthUserInfo(
        email=user_info["email"],
        first_name=user_info.get("given_name"),
        last_name=user_info.get("family_name"),
        oauth_id=user_info["id"],
        provider="google"
    )
    
    # Login/register user
    auth_service = AuthService(db)
    return auth_service.oauth_login(oauth_user)

@router.post("/verify-token")
async def verify_token_endpoint(
    token_payload = Depends(get_current_user_token)
):
    """Verify if token is valid."""
    return {
        "valid": True,
        "user_id": token_payload.sub,
        "email": token_payload.email,
        "role": token_payload.role,
        "expires": token_payload.exp
    }

# Admin routes
@router.get("/users", dependencies=[Depends(get_current_user)])
async def list_users(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all users (admin only)."""
    from ...core.security import UserRole
    
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse.from_orm(user) for user in users]

@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: int,
    is_active: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user active status (admin only)."""
    from ...core.security import UserRole
    
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = is_active
    db.commit()
    
    return {"message": f"User {'activated' if is_active else 'deactivated'} successfully"}