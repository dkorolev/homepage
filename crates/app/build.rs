fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/");
    println!("cargo:rerun-if-changed=../../static/anthropiclimits-probe/index.html");
    println!("cargo:rerun-if-changed=../../vendor/prnui/prnui.html");
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={}", hash.trim());
    // The offline-speech commit this homepage commit records, which deployment checks out and builds.
    let tts = std::process::Command::new("git")
        .args(["rev-parse", "HEAD:vendor/offline-speech"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=OFFLINE_SPEECH_COMMIT={}", tts.trim());
}
