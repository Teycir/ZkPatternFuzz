use anyhow::bail;

fn is_env_var_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_env_var_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn parse_braced_placeholder(inner: &str) -> anyhow::Result<(&str, Option<&str>)> {
    if let Some((var, default_value)) = inner.split_once(":-") {
        let var = var.trim();
        if var.is_empty() {
            bail!("Invalid placeholder '${{{}}}': empty variable name", inner);
        }
        if !var.chars().all(is_env_var_continue)
            || !is_env_var_start(var.chars().next().unwrap_or_default())
        {
            bail!(
                "Invalid placeholder '${{{}}}': variable name '{}' is not a valid identifier",
                inner,
                var
            );
        }
        return Ok((var, Some(default_value)));
    }

    let var = inner.trim();
    if var.is_empty() {
        bail!("Invalid placeholder '${{{}}}': empty variable name", inner);
    }
    if !var.chars().all(is_env_var_continue)
        || !is_env_var_start(var.chars().next().unwrap_or_default())
    {
        bail!(
            "Invalid placeholder '${{{}}}': variable name '{}' is not a valid identifier",
            inner,
            var
        );
    }
    Ok((var, None))
}

pub fn expand_env_placeholders(input: &str) -> anyhow::Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut out = String::new();

    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j >= chars.len() {
                bail!("Unterminated environment placeholder in '{}'", input);
            }

            let inner: String = chars[i + 2..j].iter().collect();
            let (var, default_value) = parse_braced_placeholder(&inner)?;
            match std::env::var(var) {
                Ok(value) => {
                    // bash-style ${VAR:-default}: use default for unset OR empty
                    if value.is_empty() {
                        if let Some(default_value) = default_value {
                            out.push_str(default_value);
                        } else {
                            out.push_str(&value);
                        }
                    } else {
                        out.push_str(&value);
                    }
                }
                Err(std::env::VarError::NotPresent) => {
                    if let Some(default_value) = default_value {
                        out.push_str(default_value);
                    } else {
                        bail!(
                            "Unresolved environment placeholder '${{{}}}' in '{}'",
                            var,
                            input
                        );
                    }
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    bail!("Environment variable '{}' is not valid Unicode", var)
                }
            }
            i = j + 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && is_env_var_start(chars[j]) {
            while j < chars.len() && is_env_var_continue(chars[j]) {
                j += 1;
            }
            let var: String = chars[i + 1..j].iter().collect();
            match std::env::var(&var) {
                Ok(value) => out.push_str(&value),
                // Keep literal $VAR when VAR is not set; this avoids rejecting paths
                // that intentionally contain '$' characters.
                Err(std::env::VarError::NotPresent) => {
                    out.push('$');
                    out.push_str(&var);
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    bail!("Environment variable '{}' is not valid Unicode", var)
                }
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    Ok(out)
}

pub fn has_unresolved_env_placeholder(input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '$' {
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j < chars.len() {
                let inner: String = chars[i + 2..j].iter().collect();
                if parse_braced_placeholder(&inner).is_ok() {
                    return true;
                }
                i = j + 1;
                continue;
            }
            return true;
        }

        i += 1;
    }
    false
}
