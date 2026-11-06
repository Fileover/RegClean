fn main() {
    println!("cargo:rerun-if-changed=CleanReg.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("CleanReg.ico");
    resource.set("ProductName", "RegClean");
    resource.set("FileDescription", "RegClean");
    resource.set("LegalCopyright", "MIT License");
    if let Err(error) = resource.compile() {
        panic!("failed to embed CleanReg.ico: {error}");
    }
}
