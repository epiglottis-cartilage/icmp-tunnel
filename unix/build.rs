fn main() {
    #[cfg(not(target_family = "unix"))]
    panic!("Support only Linux");
}
