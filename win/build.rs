fn main() {
    #[cfg(not(target_family = "windows"))]
    panic!("Support only Windows");

    #[cfg(target_arch = "x86_64")]
    println!("cargo::rustc-link-search=win/WinDivert/x64");
    #[cfg(target_arch = "x86")]
    println!("cargo::rustc-link-search=win/WinDivert/x86");
}
