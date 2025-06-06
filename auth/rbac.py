# auth/rbac.py

ROLE_PERMISSIONS = {
    "admin": ["upload", "download", "delete", "manage_users"],
    "maintainer": ["upload", "download"],
    "guest": ["download"]
}

def is_allowed(role, action):
    """بررسی اینکه نقش اجازه انجام عملیات خاصی رو داره یا نه"""
    allowed = action in ROLE_PERMISSIONS.get(role, [])
    print(f"[RBAC] Role '{role}' trying to '{action}' -> {'✔️ Allowed' if allowed else '❌ Denied'}")
    return allowed

# تست
if __name__ == "__main__":
    print(is_allowed("admin", "upload"))      # True
    print(is_allowed("guest", "delete"))       # False
    print(is_allowed("maintainer", "download"))# True
