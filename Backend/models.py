from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

try:
    from Backend.database import Base
except ImportError:
    from database import Base

class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    machine_id = Column(String, nullable=True)
    account_username = Column(String, nullable=True, index=True)
    plan_code = Column(String, nullable=True)
    source = Column(String, default="legacy")
    notes = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    expiration_date = Column(DateTime(timezone=True), nullable=True)
    duration_days = Column(Integer, default=30)  # 30, 90, 365
    
    # Session Rotation Fields
    session_id = Column(String, nullable=True, index=True)
    session_key = Column(String, nullable=True)  # Dynamic key for current session
    session_expiration = Column(DateTime(timezone=True), nullable=True)
    
class ModuleVersion(Base):
    """Stores the encrypted python code modules"""
    __tablename__ = "modules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True) # e.g., "shopee_chat", "shopee_product"
    version = Column(String, default="1.0.0")
    encrypted_code = Column(Text) # Base64 encoded encrypted string
    hash_checksum = Column(String) # For integrity check
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class WebUser(Base):
    __tablename__ = "web_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)


class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    name = Column(String, nullable=False)
    duration_label = Column(String, nullable=True)
    duration_days = Column(Integer, default=30)
    max_devices = Column(Integer, default=1)
    is_active = Column(Boolean, default=True)
    is_trial = Column(Boolean, default=False)
    sort_order = Column(Integer, default=100)
    price_amount = Column(Integer, default=0)
    currency = Column(String, default="VND")
    price_note = Column(String, nullable=True)
    external_price_ref = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class CustomerSubscription(Base):
    __tablename__ = "customer_subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    plan_code = Column(String, nullable=False, index=True)
    status = Column(String, default="active", index=True)
    starts_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    max_devices = Column(Integer, default=1)
    purchase_ref = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)


class DeviceActivation(Base):
    __tablename__ = "device_activations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    machine_id = Column(String, index=True, nullable=False)
    device_name = Column(String, nullable=True)
    device_binding_hash = Column(String, nullable=True)
    status = Column(String, default="pending", index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    binding_updated_at = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    license_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    notes = Column(Text, nullable=True)
