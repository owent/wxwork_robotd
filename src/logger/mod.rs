use std::cell::{RefCell, RefMut};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use log;
use log::{Level, Log, Metadata, Record, SetLoggerError};
use time;

struct FileRotateLoggerRuntime {
    pub current_rotate: i32,
    pub current_size: usize,
    pub current_file: Option<File>,
}

struct FileRotateLogger {
    pub level: Level,
    pub file_path: String,
    pub rotate_num: i32,
    pub rotate_size: usize,
    pub runtime: Arc<Mutex<RefCell<FileRotateLoggerRuntime>>>,
}

enum FileRotateLoggerWrapper {
    Logger(FileRotateLogger),
    Nil,
}

impl FileRotateLogger {
    fn next_file(&self, runtime: &mut RefMut<FileRotateLoggerRuntime>) -> bool {
        if let Some(ref file) = runtime.current_file {
            if let Err(e) = file.sync_all() {
                eprintln!("Try to sync log file failed: {:?}", e);
            }
            drop(file);
        }

        runtime.current_rotate = (runtime.current_rotate + 1) % self.rotate_num;
        let file_path = get_log_path(self.file_path.as_str(), runtime.current_rotate);

        let mut options = OpenOptions::new();
        options.create(true).append(true).truncate(true);
        if let Ok(file) = options.open(file_path) {
            runtime.current_file = Some(file);
            runtime.current_size = 0;
        }

        true
    }
}

impl Log for FileRotateLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let guard = match self.runtime.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    eprintln!("Try to lock logger failed");
                    return;
                }
            };

            let runtime_rc = &*guard;
            let mut runtime = runtime_rc.borrow_mut();

            // open log file for the first time
            if let None = runtime.current_file {
                let full_file_path = get_log_path(self.file_path.as_str(), runtime.current_rotate);
                let file_path = Path::new(full_file_path.as_str());
                if let Some(dir_path) = file_path.parent() {
                    if !dir_path.as_os_str().is_empty()
                        && (!dir_path.exists() || !dir_path.is_dir())
                    {
                        if create_dir_all(dir_path).is_err() {
                            eprintln!("Try to create log directory {:?} failed", dir_path);
                        }
                    }
                }

                let mut options = OpenOptions::new();
                options.create(true).append(true).truncate(false);
                if let Ok(file) = options.open(file_path) {
                    if let Ok(meta) = file.metadata() {
                        runtime.current_size = meta.len() as usize;
                    } else {
                        eprintln!("Try to read meta of log file {} failed", full_file_path);
                    }
                    runtime.current_file = Some(file);
                } else {
                    eprintln!("Try to open log file {} failed", full_file_path);
                }

                if runtime.current_size >= self.rotate_size {
                    self.next_file(&mut runtime);
                }
            }

            let mut written_len = 0;
            if let Some(ref mut file) = runtime.current_file {
                let content = format!(
                    "{} {:<5} [{}] {}\n",
                    time::strftime("%Y-%m-%d %H:%M:%S", &time::now()).unwrap(),
                    record.level().to_string(),
                    record.module_path().unwrap_or_default(),
                    record.args(),
                );

                if let Ok(len) = file.write(content.as_bytes()) {
                    written_len = len;
                }
            }
            runtime.current_size += written_len;

            if runtime.current_size >= self.rotate_size {
                self.next_file(&mut runtime);
            }
        }
    }

    fn flush(&self) {
        let guard = match self.runtime.lock() {
            Ok(guard) => guard,
            Err(_) => {
                eprintln!("Try to lock logger failed");
                return;
            }
        };

        let runtime_rc = &*guard;
        let runtime = runtime_rc.borrow_mut();

        // flush into device
        if let Some(ref file) = runtime.current_file {
            if let Err(e) = file.sync_all() {
                eprintln!("Try to sync log file failed: {:?}", e);
            }
        }
    }
}

fn get_log_path(file_path: &str, rotate_num: i32) -> String {
    return format!("{}.{}", file_path, rotate_num);
}

static mut SHARED_FILE_ROTATE_LOG: FileRotateLoggerWrapper = FileRotateLoggerWrapper::Nil;

/// Initializes the global logger with a FileRotateLogger instance with
/// `max_log_level` set to a specific log level.
///
/// ```
/// # #[macro_use] extern crate log;
/// # extern crate logger;
/// #
/// # fn main() {
/// logger::init_with_level(log::Level::Warn).unwrap();
///
/// warn!("This is an example message.");
/// info!("This message will not be logged.");
/// # }
/// ```
pub fn init_with_level(
    level: Level,
    file_path: &str,
    rotate_num: i32,
    rotate_size: usize,
) -> Result<(), SetLoggerError> {
    let mut init_rotate = 0;
    let mut last_modify_time = SystemTime::UNIX_EPOCH.clone();
    for idx in 0..rotate_num {
        let test_file_path = get_log_path(file_path, idx);
        let test_file = File::open(test_file_path);
        if let Ok(file) = test_file {
            if let Ok(meta) = file.metadata() {
                if let Ok(time) = meta.modified() {
                    if time > last_modify_time {
                        last_modify_time = time.clone();
                        init_rotate = idx;
                    }
                }
            }
        } else {
            init_rotate = if idx > 0 { idx - 1 } else { idx };
            break;
        }
    }

    unsafe {
        SHARED_FILE_ROTATE_LOG = FileRotateLoggerWrapper::Logger(FileRotateLogger {
            level: level,
            file_path: String::from(file_path),
            rotate_num: if rotate_num > 0 { rotate_num } else { 1 },
            rotate_size: rotate_size,
            runtime: Arc::new(Mutex::new(RefCell::new(FileRotateLoggerRuntime {
                current_rotate: init_rotate,
                current_size: 0,
                current_file: None,
            }))),
        });

        if let FileRotateLoggerWrapper::Logger(ref l) = SHARED_FILE_ROTATE_LOG {
            log::set_logger(l)?;
        }
    }
    // log::set_boxed_logger(logger_inst)?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

/// Initializes the global logger with a FileRotateLogger instance with
/// `max_log_level` set to `LogLevel::Trace`.
///
/// ```
/// # #[macro_use] extern crate log;
/// # extern crate logger;
/// #
/// # fn main() {
/// logger::init().unwrap();
/// warn!("This is an example message.");
/// # }
/// ```
pub fn init(file_path: &str, rotate_num: i32, rotate_size: usize) -> Result<(), SetLoggerError> {
    init_with_level(Level::Info, file_path, rotate_num, rotate_size)
}
