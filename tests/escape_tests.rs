//! Tentatives d'évasion réelles. Chaque test vérifie qu'une action que
//! `hajiz` prétend bloquer échoue effectivement.
//!
//! Différence avec `exploit_tests.rs` : ces tests *attaquent* le sandbox
//! (lectures interdites, syscalls dangereux, écritures hors whitelist...)
//! au lieu de simplement vérifier qu'un binaire s'exécute.

use std::path::Path;
use std::process::Command;

fn hajiz() -> String {
    std::env::var("HAJIZ_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_hajiz").to_string())
}

fn landlock_supported() -> bool {
    let out = Command::new(hajiz())
        .arg("--kernel-info")
        .output()
        .expect("hajiz --kernel-info");
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find(|l| l.contains("landlock"))
        .map(|l| l.contains("oui") || l.contains("yes") || l.contains("true"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Hardening général
// ---------------------------------------------------------------------------

/// no_new_privs doit être activé dans le sandbox : empêche execve d'un
/// binaire setuid de gagner des privilèges.
#[test]
fn escape_no_new_privs_is_set() {
    let out = Command::new(hajiz())
        .args(["/usr/bin/cat", "/proc/self/status"])
        .output()
        .expect("lancement hajiz");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .expect("NoNewPrivs absent de /proc/self/status");
    assert!(
        line.contains("1"),
        "NoNewPrivs doit être activé dans le sandbox, got: {line:?}"
    );
}

// ---------------------------------------------------------------------------
// Hardening seccomp : syscalls dangereux
// ---------------------------------------------------------------------------

/// keyctl est dans la liste des syscalls bloqués par le hardening filter.
/// Le binaire keyctl doit échouer à manipuler le keyring.
#[test]
fn escape_keyctl_syscall_blocked() {
    if !Path::new("/usr/bin/keyctl").exists() {
        eprintln!("[skip] /usr/bin/keyctl absent");
        return;
    }
    let out = Command::new(hajiz())
        .args(["/usr/bin/keyctl", "show"])
        .output()
        .expect("lancement hajiz");
    assert!(
        !out.status.success(),
        "keyctl show ne doit pas réussir : le syscall keyctl est interdit par le filtre de durcissement"
    );
}

/// Le syscall bpf() doit être refusé. On le déclenche depuis Python via
/// ctypes pour éviter d'avoir besoin d'un binaire dédié.
#[test]
fn escape_bpf_syscall_returns_eperm() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("[skip] python3 absent");
        return;
    }
    let probe = "
import ctypes, errno, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)
# SYS_bpf == 321 sur x86_64
ret = libc.syscall(321, 0, 0, 0)
err = ctypes.get_errno()
# Sans seccomp : EINVAL (mauvais args). Avec seccomp hardening : EPERM.
sys.exit(0 if (ret == -1 and err == errno.EPERM) else 1)
";
    let out = Command::new(hajiz())
        .args(["/usr/bin/python3", "--", "-c", probe])
        .output()
        .expect("lancement hajiz");
    assert!(
        out.status.success(),
        "bpf() doit retourner EPERM sous seccomp hardening, got status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Filesystem : Landlock
// ---------------------------------------------------------------------------

/// Avec une allowlist Landlock restrictive (/usr ro + /tmp rw), la lecture
/// d'un fichier hors whitelist (/etc) doit échouer.
#[test]
fn escape_fs_read_outside_allowlist_blocked() {
    if !landlock_supported() {
        eprintln!("[skip] Landlock indisponible sur ce kernel");
        return;
    }
    let out = Command::new(hajiz())
        .args([
            "--fs", "/usr:ro",
            "--fs", "/tmp:rw",
            "/usr/bin/cat", "/etc/hostname",
        ])
        .output()
        .expect("lancement hajiz");
    assert!(
        !out.status.success(),
        "cat /etc/hostname ne doit pas réussir avec Landlock limité à /usr+/tmp"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Permission") || stderr.contains("denied") || stderr.contains("permis"),
        "stderr doit mentionner un refus d'accès, got: {stderr}"
    );
}

/// Avec /usr en read-only via Landlock, dd doit échouer à écrire dans /usr.
/// (Le user n'a normalement pas non plus le droit, mais Landlock garantit
/// le refus indépendamment des permissions UNIX classiques.)
#[test]
fn escape_fs_write_outside_rules_blocked() {
    if !landlock_supported() {
        eprintln!("[skip] Landlock indisponible");
        return;
    }
    // Cible dans le home du test : sans hajiz l'utilisateur peut y écrire,
    // donc un succès indique une vraie évasion. Avec hajiz et /home non
    // whitelisté, l'écriture doit échouer.
    let target = format!(
        "{}/hajiz_escape_test_{}.tmp",
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
        std::process::id()
    );
    let _ = std::fs::remove_file(&target);

    let out = Command::new(hajiz())
        .args([
            "--fs", "/usr:ro",
            "--fs", "/tmp:rw",
            "/usr/bin/dd",
            "if=/dev/zero",
            &format!("of={}", target),
            "bs=1",
            "count=1",
        ])
        .output()
        .expect("lancement hajiz");

    let wrote = Path::new(&target).exists();
    let _ = std::fs::remove_file(&target);

    assert!(
        !out.status.success() && !wrote,
        "dd a écrit {target} alors que $HOME n'est pas whitelisté Landlock — évasion filesystem"
    );
}

// ---------------------------------------------------------------------------
// Kill-on-deny : la sandbox tue le processus, pas juste EPERM
// ---------------------------------------------------------------------------

/// Avec --seccomp-whitelist sans network group + --kill-on-deny, un appel
/// à socket() doit faire mourir le processus par SIGSYS (signal 31), pas
/// renvoyer EPERM.
#[test]
fn escape_kill_on_deny_terminates_with_sigsys() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("[skip] python3 absent");
        return;
    }
    let probe = "
import socket, sys
try:
    socket.socket()
except Exception:
    sys.exit(0)
# Si on arrive ici, socket() a réussi → évasion.
sys.exit(99)
";
    let out = Command::new(hajiz())
        .args([
            "--seccomp-whitelist",
            "--allow-group", "io",
            "--allow-group", "memory",
            "--allow-group", "threading",
            "--allow-group", "process",
            "--kill-on-deny",
            "/usr/bin/python3", "--", "-c", probe,
        ])
        .output()
        .expect("lancement hajiz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "hajiz doit retourner une erreur quand l'enfant meurt par SIGSYS, \
         status={:?}, stderr={stderr}",
        out.status
    );
    // hajiz n'hérite pas du signal de l'enfant : il l'inscrit dans stderr et
    // dans la télémétrie (champ signal=31). On vérifie la trace.
    assert!(
        stderr.contains("SIGSYS") || stderr.contains("signal: 31"),
        "stderr doit indiquer une mort par SIGSYS (kill_on_deny actif), got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Audit mode : la commande produit un profil exploitable
// ---------------------------------------------------------------------------

/// Le mode --audit produit un profil TOML contenant au moins une section
/// [seccomp] avec des syscalls observés.
#[test]
fn escape_audit_mode_generates_profile() {
    if Command::new("strace").arg("--version").output().is_err() {
        eprintln!("[skip] strace absent");
        return;
    }
    let out_path = format!("/tmp/hajiz_audit_{}.toml", std::process::id());
    let _ = std::fs::remove_file(&out_path);

    let out = Command::new(hajiz())
        .args([
            "--audit",
            "--audit-output", &out_path,
            "/usr/bin/echo", "ok",
        ])
        .output()
        .expect("lancement hajiz");

    let profile = std::fs::read_to_string(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);

    assert!(
        out.status.success() || out.status.code() == Some(0),
        "audit mode doit terminer normalement, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        profile.contains("[seccomp]") && profile.contains("allow_syscalls"),
        "le profil doit contenir une section seccomp avec allow_syscalls, got:\n{profile}"
    );
}
