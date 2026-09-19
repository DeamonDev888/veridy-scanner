use std::io::Read;
use std::str::FromStr;

/// Échappement JSON conforme RFC 8259 : \\, \", \b, \f, \n, \r, \t
/// et tous les caractères de contrôle U+0000..U+001F en \u00XX.
#[allow(dead_code)]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Extrait la valeur d'une clé chaîne dans un document JSON.
/// Clé quotée UNIQUEMENT : évite le faux positif "domain" matchant "subdomain".
pub fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":", key);
    let pos = json.find(&pattern)?;
    let rest = json[pos + pattern.len()..].trim_start();
    let inside = rest.strip_prefix('"')?;
    let mut val = String::new();
    let mut escaped = false;
    for ch in inside.chars() {
        if escaped {
            val.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(val);
        } else {
            val.push(ch);
        }
    }
    None
}

/// Extrait une valeur numérique depuis une portion de JSON
pub fn extract_json_num<T: FromStr>(json: &str, key: &str) -> Option<T> {
    let pattern = format!("\"{}\":", key);
    if let Some(pos) = json.find(&pattern) {
        let rest = json[pos + pattern.len()..].trim_start();
        let num_str: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
            .collect();
        return num_str.parse::<T>().ok();
    }
    None
}

/// Extrait une valeur booléenne depuis une portion de JSON
pub fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", key);
    if let Some(pos) = json.find(&pattern) {
        let rest = json[pos + pattern.len()..].trim_start();
        if rest.starts_with("true") {
            return Some(true);
        } else if rest.starts_with("false") {
            return Some(false);
        }
    }
    None
}

/// Horodatage ISO 8601 UTC calculé en Rust pur — aucun sous-processus `date`,
/// aucun fallback hardcodé : dépend uniquement de l'horloge système.
pub fn iso_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Jours écoulés depuis l'epoch → date civile (algorithme Howard Hinnant).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Sanitization stricte pour noms de fichiers temporaires : whitelist [a-zA-Z0-9-],
/// tout le reste en '_' (bloque '/', '..' et tout méta-caractère de chemin).
pub fn sanitize_target(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "target".to_string()
    } else {
        cleaned
    }
}

/// Exécute un binaire avec deadline stricte : spawn, lecture des pipes dans des
/// threads (aucun deadlock de buffer 64 Ko), kill au dépassement. stdin = /dev/null.
/// Retourne None si le binaire est introuvable OU en timeout (kill).
/// L'outil est-il présent et exécutable sur le PATH ?
pub fn tool_on_path(bin: &str) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = std::path::Path::new(dir).join(bin);
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

/// Probe TCP connect (timeout court) — true si le port répond.
pub fn tcp_probe(host: &str, port: u16) -> bool {
    use std::io::Write;
    use std::net::TcpStream;
    let addr = format!("{}:{}", host, port);
    let Ok(mut stream) = TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:1".parse().unwrap()),
        std::time::Duration::from_millis(600),
    ) else {
        return false;
    };
    // certains services ne comptent "ouverts" qu'après un échange ; envoie un byte bénin
    let _ = stream.write_all(b"\r\n");
    true
}

pub fn run_tool(bin: &str, args: &[&str], timeout_secs: u64) -> Option<std::process::Output> {
    run_tool_env(bin, args, timeout_secs, &[])
}

/// Variante de run_tool avec variables d'environnement (PGCONNECT_TIMEOUT, ...).
pub fn run_tool_env(
    bin: &str,
    args: &[&str],
    timeout_secs: u64,
    envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let t_out = std::thread::spawn(move || read_all(stdout_pipe));
    let t_err = std::thread::spawn(move || read_all(stderr_pipe));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    };
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    status.map(|s| std::process::Output {
        status: s,
        stdout,
        stderr,
    })
}

/// Variante avec entrée stdin (psql -f -). Le stdin est fermé après écriture (EOF).
pub fn run_tool_stdin(
    bin: &str,
    args: &[&str],
    timeout_secs: u64,
    input: &str,
    envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    use std::io::Write as _;
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().ok()?;
    let stdin = child.stdin.take();
    let input_owned = input.to_string();
    let t_in = std::thread::spawn(move || {
        if let Some(mut s) = stdin {
            let _ = s.write_all(input_owned.as_bytes());
        }
    });
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let t_out = std::thread::spawn(move || read_all(stdout_pipe));
    let t_err = std::thread::spawn(move || read_all(stderr_pipe));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    };
    let _ = t_in.join();
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    status.map(|s| std::process::Output {
        status: s,
        stdout,
        stderr,
    })
}

fn read_all<R: Read>(mut pipe: Option<R>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(p) = pipe.as_mut() {
        let _ = p.read_to_end(&mut buf);
    }
    buf
}
