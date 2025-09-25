import secrets
import hashlib
import time
from typing import List, Dict, Optional
from datetime import datetime, timezone
from functools import wraps

# ====================================================
# Security configuration (no external .env/jwt needed)
# ====================================================
SECRET_KEY = secrets.token_hex(32)
TOKEN_EXPIRATION_SECONDS = 1800  # 30 minutes
active_tokens = {}  # in-memory token store

# ====================================================
# In-memory mock database
# ====================================================
supply_chain_data = {
    "products": {
        "P001": {"name": "Laptop", "category": "Electronics", "price": 1200, "stock": 50, "min_stock_level": 10},
        "P002": {"name": "Smartphone", "category": "Electronics", "price": 800, "stock": 100, "min_stock_level": 20},
        "P003": {"name": "Office Chair", "category": "Furniture", "price": 250, "stock": 20, "min_stock_level": 5},
    },
    "orders": {},
    "suppliers": {},
    "users": {
        "admin": {
            "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
            "role": "admin",
            "is_active": True
        },
        "manager": {
            "password_hash": hashlib.sha256("manager123".encode()).hexdigest(),
            "role": "manager", 
            "is_active": True
        },
        "viewer": {
            "password_hash": hashlib.sha256("viewer123".encode()).hexdigest(),
            "role": "viewer",
            "is_active": True
        }
    },
    "audit_log": []
}

# ====================================================
# Security utilities
# ====================================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_token(username: str, role: str) -> str:
    token = secrets.token_hex(16)
    active_tokens[token] = {
        "sub": username,
        "role": role,
        "exp": time.time() + TOKEN_EXPIRATION_SECONDS
    }
    return token

def verify_token(token: str) -> Optional[dict]:
    data = active_tokens.get(token)
    if not data:
        return None
    if time.time() > data["exp"]:
        del active_tokens[token]
        return None
    return data

def log_audit_event(username: str, action: str, details: str):
    timestamp = datetime.now(timezone.utc).isoformat()
    supply_chain_data["audit_log"].append({
        "timestamp": timestamp,
        "username": username,
        "action": action,
        "details": details
    })

# ====================================================
# Authentication decorator
# ====================================================
def require_auth(required_roles: List[str] = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = kwargs.pop("auth_token", None)
            if not token:
                return "Authentication required. Please provide auth_token."

            payload = verify_token(token)
            if not payload:
                return "Invalid or expired authentication token."

            username = payload["sub"]
            role = payload["role"]

            user = supply_chain_data["users"].get(username)
            if not user or not user["is_active"]:
                return "User account not found or inactive."

            if required_roles and role not in required_roles:
                return f"Access denied. Required roles: {', '.join(required_roles)}"

            log_audit_event(username, f"tool_{func.__name__}", f"Executed {func.__name__} with args: {args}, {kwargs}")

            # Inject user context
            kwargs["current_user"] = username
            kwargs["user_role"] = role

            return func(*args, **kwargs)
        return wrapper
    return decorator

# ====================================================
# Core functionality
# ====================================================
def login(username: str, password: str) -> str:
    user = supply_chain_data["users"].get(username)
    if not user or not user["is_active"]:
        return "Invalid username or account inactive."
    if not verify_password(password, user["password_hash"]):
        return "Invalid password."
    token = create_token(username, user["role"])
    log_audit_event(username, "login_success", "User logged in successfully")
    return f"Login successful. Your authentication token: {token}"

@require_auth(["admin", "manager", "viewer"])
def check_product_stock(product_id: str, **kwargs) -> str:
    product = supply_chain_data["products"].get(product_id)
    if product:
        low_stock_warning = " (LOW STOCK!)" if product["stock"] <= product["min_stock_level"] else ""
        return f"{product['name']} (ID: {product_id}) has {product['stock']} units in stock.{low_stock_warning}"
    return "Product ID not found."

@require_auth(["admin"])
def view_audit_log(**kwargs) -> str:
    logs = supply_chain_data["audit_log"]
    if not logs:
        return "No audit log entries."
    return "\n".join([f"{log['timestamp']} | {log['username']} | {log['action']} | {log['details']}" for log in logs])

# ====================================================
# Demo run
# ====================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Secure Supply Chain Management System (Simplified)")
    print("=" * 60)
    print("Demo users created:")
    print("• admin / admin123 (Admin)")
    print("• manager / manager123 (Manager)")
    print("• viewer / viewer123 (Viewer)")
    print("")

    # Example run
    print(">>> Logging in as admin...")
    login_response = login("admin", "admin123")
    print(login_response)

    # Extract token cleanly
    if "authentication token:" in login_response:
        token_value = login_response.split("authentication token: ")[-1].strip()

        print(">>> Checking product stock...")
        print(check_product_stock("P001", auth_token=token_value))

        print(">>> Viewing audit log...")
        print(view_audit_log(auth_token=token_value))
