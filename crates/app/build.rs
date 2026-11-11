/// The trimmed output of `git <args>`, or nothing when Git or its repository is unavailable.
fn git(args: &[&str]) -> String {
  std::process::Command::new("git")
    .args(args)
    .output()
    .ok()
    .filter(|output| output.status.success())
    .and_then(|output| String::from_utf8(output.stdout).ok())
    .map(|stdout| stdout.trim().to_string())
    .unwrap_or_default()
}

fn main() {
  println!("cargo:rerun-if-changed=../../.git/HEAD");
  println!("cargo:rerun-if-changed=../../.git/refs/");
  println!("cargo:rerun-if-changed=../../static/anthropiclimits-probe/index.html");
  println!("cargo:rerun-if-changed=../../vendor/prnui/prnui.html");
  println!("cargo:rustc-env=GIT_HASH={}", git(&["rev-parse", "--short=7", "HEAD"]));
  // The offline-speech commit this homepage commit records, which deployment checks out and builds.
  println!("cargo:rustc-env=OFFLINE_SPEECH_COMMIT={}", git(&["rev-parse", "HEAD:vendor/offline-speech"]));
}
