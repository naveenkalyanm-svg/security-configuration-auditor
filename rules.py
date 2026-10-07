# =========================================================
# SSH SECURITY RULES
# =========================================================

SSH_RULES = [
    {
        "rule_id": "SSH-001",
        "setting": "PermitRootLogin",
        "expected": "no",
        "title": "Root login is enabled",
        "description": "Direct SSH login as root is allowed.",
        "severity": "High",
        "recommendation": "Set PermitRootLogin to no."
    },
    {
        "rule_id": "SSH-002",
        "setting": "PasswordAuthentication",
        "expected": "no",
        "title": "Password authentication is enabled",
        "description": "SSH allows password-based authentication.",
        "severity": "Medium",
        "recommendation": "Disable password authentication and use SSH keys."
    }
]


# =========================================================
# DOCKER SECURITY RULES
# =========================================================

DOCKER_RULES = [
    {
        "rule_id": "DOCKER-001",
        "instruction": "USER",
        "expected": "non-root",
        "title": "Docker container runs as root",
        "description": "The Dockerfile does not specify a non-root user.",
        "severity": "High",
        "recommendation": "Create and use a non-root user with the USER instruction."
    },
    {
        "rule_id": "DOCKER-002",
        "instruction": "EXPOSE",
        "expected": "restricted",
        "title": "Potentially exposed service port",
        "description": "The Dockerfile exposes a network service port.",
        "severity": "Medium",
        "recommendation": "Expose only the ports that are required by the application."
    }
]


# =========================================================
# NGINX SECURITY RULES
# =========================================================

NGINX_RULES = [
    {
        "rule_id": "NGINX-001",
        "directive": "server_tokens",
        "expected": "off",
        "title": "NGINX version information is exposed",
        "description": "NGINX may reveal its version information in server responses.",
        "severity": "Low",
        "recommendation": "Set server_tokens off."
    },
    {
        "rule_id": "NGINX-002",
        "directive": "autoindex",
        "expected": "off",
        "title": "Directory listing may be enabled",
        "description": "NGINX directory indexing can expose files and directory information.",
        "severity": "Medium",
        "recommendation": "Set autoindex off."
    }
]