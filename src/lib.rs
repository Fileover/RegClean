#[cfg(not(windows))]
compile_error!("regclean supports Windows only");

pub mod backup;
pub mod cli;
pub mod exclusions;
pub mod fix;
pub mod gui;
pub mod model;
pub mod paths;
pub mod registry;
pub mod report;
pub mod scan;
