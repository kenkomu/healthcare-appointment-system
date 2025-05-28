from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import Optional
import hashlib
import secrets

from ..models.user import User, RefreshToken
from ..core.security import (
    verify_password, get_password_hash, create_token_pair,
    verify_token, TokenPayload, UserRole, generate_password_reset_token
)
from ..schemas.auth import (
    UserLogin, UserRegister, TokenResponse, UserResponse,
    OAuthUserInfo, PasswordReset, PasswordResetConfirm
)

class AuthService:
    def __init__(self, db: Session):
        self.db = db
    
    def register_user(self, user_data: UserRegister) -> User:
        """Register a new user."""
        # Check if user already exists
        existing_user = self.db.query(User).filter(
            User.email == user_data.email
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        hashed_password = get_password_hash(user_data.password)
        
        new_user = User(
            email=user_data.email,
            password_hash=hashed_password,
            role=user_data.role,
            is_active=True,
            is_verified=False  # Require email verification
        )
        
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
        
        return new_user
    
    def authenticate_user(self, login_data: UserLogin) -> TokenResponse:
        """Authenticate user and return tokens."""
        user = self.db.query(User).filter(
            User.email == login_data.email
        ).first()
        
        if not user:
            self._handle_failed_login(login_data.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check account lockout
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked"
            )
        
        # Verify password
        if not user.password_hash or not verify_password(
            login_data.password, user.password_hash
        ):
            self._handle_failed_login(login_data.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        
        # Create tokens
        tokens = create_token_pair(user.id, user.email, user.role)
        
        # Store refresh token
        self._store_refresh_token(user.id, tokens.refresh_token)
        
        self.db.commit()
        
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            user=UserResponse.from_orm(user)
        )
    
    def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        """Refresh access token using refresh token."""
        # Verify refresh token
        token_payload = verify_token(refresh_token)
        if not token_payload or token_payload.token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Check if refresh token exists in database
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        stored_token = self.db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.utcnow()
        ).first()
        
        if not stored_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Get user
        user = self.db.query(User).filter(
            User.id == token_payload.sub
        ).first()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new tokens
        new_tokens = create_token_pair(user.id, user.email, user.role)
        
        # Revoke old refresh token and store new one
        stored_token.is_revoked = True
        self._store_refresh_token(user.id, new_tokens.refresh_token)
        
        self.db.commit()
        
        return TokenResponse(
            access_token=new_tokens.access_token,
            refresh_token=new_tokens.refresh_token,
            token_type=new_tokens.token_type,
            expires_in=new_tokens.expires_in,
            user=UserResponse.from_orm(user)
        )
    
    def logout_user(self, refresh_token: str) -> bool:
        """Logout user by revoking refresh token."""
        try:
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            stored_token = self.db.query(RefreshToken).filter(
                RefreshToken.token_hash == token_hash
            ).first()
            
            if stored_token:
                stored_token.is_revoked = True
                self.db.commit()
            
            return True
        except Exception:
            return False
    
    def oauth_login(self, oauth_data: OAuthUserInfo) -> TokenResponse:
        """Handle OAuth login/registration."""
        # Check if user exists with OAuth ID
        user = self.db.query(User).filter(
            User.oauth_provider == oauth_data.provider,
            User.oauth_id == oauth_data.oauth_id
        ).first()
        
        if not user:
            # Check if user exists with same email
            user = self.db.query(User).filter(
                User.email == oauth_data.email
            ).first()
            
            if user:
                # Link OAuth account to existing user
                user.oauth_provider = oauth_data.provider
                user.oauth_id = oauth_data.oauth_id
            else:
                # Create new user
                user = User(
                    email=oauth_data.email,
                    role=UserRole.PATIENT,  # Default role for OAuth users
                    oauth_provider=oauth_data.provider,
                    oauth_id=oauth_data.oauth_id,
                    is_active=True,
                    is_verified=True  # OAuth users are pre-verified
                )
                self.db.add(user)
        
        user.last_login = datetime.utcnow()
        
        # Create tokens
        tokens = create_token_pair(user.id, user.email, user.role)
        self._store_refresh_token(user.id, tokens.refresh_token)
        
        self.db.commit()
        self.db.refresh(user)
        
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            user=UserResponse.from_orm(user)
        )
    
    def request_password_reset(self, email: str) -> bool:
        """Generate password reset token."""
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            # Don't reveal if email exists
            return True
        
        # Generate reset token
        reset_token = generate_password_reset_token()
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        self.db.commit()
        
        # TODO: Send email with reset token
        return True
    
    def reset_password(self, reset_data: PasswordResetConfirm) -> bool:
        """Reset password using reset token."""
        user = self.db.query(User).filter(
            User.password_reset_token == reset_data.token,
            User.password_reset_expires > datetime.utcnow()
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Update password
        user.password_hash = get_password_hash(reset_data.new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Revoke all refresh tokens
        self.db.query(RefreshToken).filter(
            RefreshToken.user_id == user.id
        ).update({"is_revoked": True})
        
        self.db.commit()
        return True
    
    def _handle_failed_login(self, email: str):
        """Handle failed login attempt."""
        user = self.db.query(User).filter(User.email == email).first()
        if user:
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            
            self.db.commit()
    
    def _store_refresh_token(self, user_id: int, refresh_token: str):
        """Store refresh token in database."""
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Decode token to get expiration
        token_payload = verify_token(refresh_token)
        expires_at = datetime.fromtimestamp(token_payload.exp) if token_payload and token_payload.exp else datetime.utcnow() + timedelta(days=7)
        
        # Remove old refresh tokens for this user (optional: keep last N tokens)
        self.db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id
        ).update({"is_revoked": True})
        
        # Store new refresh token
        new_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        self.db.add(new_token)
    
    def cleanup_expired_tokens(self):
        """Clean up expired refresh tokens."""
        self.db.query(RefreshToken).filter(
            RefreshToken.expires_at < datetime.utcnow()
        ).update({"is_revoked": True})
        
        self.db.commit()