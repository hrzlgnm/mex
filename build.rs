//! Windows executable metadata: icon plus version info.
//!
//! The `winresource` build dependency only exists on Windows
//! (`target.'cfg(windows)'.build-dependencies`), so this whole block
//! compiles out everywhere else.

#![forbid(unsafe_code)]

fn main() {
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("packaging/windows/mex.ico");
        resource.set("FileDescription", env!("CARGO_PKG_DESCRIPTION"));
        resource.set("LegalCopyright", "Copyright 2026 hrzlgnm");
        resource.set("OriginalFilename", "mex.exe");
        if let Err(error) = resource.compile() {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
