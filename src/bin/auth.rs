fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = mi_clip::auth_cli::run(&arguments) {
        eprintln!("Authorization failed: {error}");
        std::process::exit(1);
    }
}
