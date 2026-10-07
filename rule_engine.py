from security.rules import SSH_RULES, DOCKER_RULES, NGINX_RULES


def run_rules(normalized_config):
    findings = []

    configuration_type = normalized_config.get("configuration_type")

    # =========================================================
    # SSH RULES
    # =========================================================

    if configuration_type == "SSH":

        settings = normalized_config.get("settings", [])

        for setting in settings:

            setting_name = setting["name"]
            current_value = setting["value"]

            for rule in SSH_RULES:

                if setting_name == rule["setting"]:

                    if current_value.lower() != rule["expected"].lower():

                        findings.append({
                            "rule_id": rule["rule_id"],
                            "title": rule["title"],
                            "setting": setting_name,
                            "current_value": current_value,
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "recommendation": rule["recommendation"],
                            "line": setting["line"]
                        })

    # =========================================================
    # DOCKER RULES
    # =========================================================

    elif configuration_type == "DOCKER":

        instructions = normalized_config.get("instructions", [])

        user_instruction_found = False

        for instruction in instructions:

            if instruction["instruction"] == "USER":
                user_instruction_found = True

        # DOCKER-001
        if not user_instruction_found:

            rule = DOCKER_RULES[0]

            findings.append({
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "setting": "USER",
                "current_value": "Not specified",
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
                "line": 0
            })

        # DOCKER-002
        for instruction in instructions:

            if instruction["instruction"] == "EXPOSE":

                rule = DOCKER_RULES[1]

                findings.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "setting": "EXPOSE",
                    "current_value": instruction["value"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "line": instruction["line"]
                })

    # =========================================================
    # NGINX RULES
    # =========================================================

    elif configuration_type == "NGINX":

        directives = normalized_config.get("directives", [])

        # Track whether security directives are present
        server_tokens_found = False
        autoindex_found = False

        for directive in directives:

            directive_name = directive["directive"]
            current_value = directive["value"]

            # NGINX-001
            if directive_name == "server_tokens":

                server_tokens_found = True

                rule = NGINX_RULES[0]

                if current_value.lower() != rule["expected"].lower():

                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "setting": directive_name,
                        "current_value": current_value,
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommendation": rule["recommendation"],
                        "line": directive["line"]
                    })

            # NGINX-002
            if directive_name == "autoindex":

                autoindex_found = True

                rule = NGINX_RULES[1]

                if current_value.lower() != rule["expected"].lower():

                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "setting": directive_name,
                        "current_value": current_value,
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommendation": rule["recommendation"],
                        "line": directive["line"]
                    })

        # If server_tokens is not specified,
        # report it as a security finding.
        if not server_tokens_found:

            rule = NGINX_RULES[0]

            findings.append({
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "setting": "server_tokens",
                "current_value": "Not specified",
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
                "line": 0
            })

        # If autoindex is not specified,
        # report it as a security finding.
        if not autoindex_found:

            rule = NGINX_RULES[1]

            findings.append({
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "setting": "autoindex",
                "current_value": "Not specified",
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
                "line": 0
            })

    return findings