fn main() {
    let cfg = slint_build::CompilerConfiguration::new().with_style("material".into());
    slint_build::compile_with_config("ui/main.slint", cfg).expect("Slint build failed");
}
