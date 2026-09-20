//! Normal Rust target: signals that main started, then waits forever.
//! The main-start event is the deterministic post-loader checkpoint.
#![cfg(windows)]
include!("../../test-support/fixture_events.rs");

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "--stork-tool-descendant")
    {
        // Deliberately leave a child for the supervisor's job to terminate.
        #[allow(clippy::zombie_processes)]
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .spawn()
            .unwrap();
        std::fs::write(&args[1], child.id().to_string()).unwrap();
        if args.get(2).is_some_and(|arg| arg == "exit") {
            return;
        }
    }
    if args.first().is_some_and(|arg| arg == "--stork-tool-output") {
        println!("captured stdout");
        eprintln!("captured stderr");
        std::process::exit(17);
    }
    if args.first().is_some_and(|arg| arg == "--stork-check-args") {
        assert_eq!(
            &args[1..],
            &[
                "",
                "space value",
                "embedded\"quote",
                "trailing\\",
                "\\\\\"mixed",
                "日本語",
                "\u{1f980}"
            ]
        );
    }
    signal(b"Local\\stork_main_");
    loop {
        unsafe { winapi::um::synchapi::Sleep(60_000) }
    }
}
