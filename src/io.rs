use std::io::Error;
use std::path::Path;

pub fn write_file(path: impl AsRef<Path>, content: &[u8]) -> Result<(), Error> {
    std::fs::create_dir_all(
        path.as_ref()
            .parent()
            .ok_or_else(|| Error::other("Path has no parent"))?,
    )?;
    std::fs::write(path, content)
}

pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    std::fs::read(path)
}

// AI-generated (but it's about what I would have done anyway)
pub fn get_config_dir() -> String {
    #[cfg(target_os = "windows")]
    {
        // Use Roaming AppData (e.g., C:\Users\Username\AppData\Roaming)
        std::env::var("APPDATA").unwrap_or(format!(
            "{}\\AppData\\Roaming",
            std::env::var("USERPROFILE").unwrap()
        ))
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Use ~/.config for Unix-like systems
        format!("{}/.config", std::env::var("HOME").unwrap())
    }
}
