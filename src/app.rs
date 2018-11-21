extern crate clap;
use clap::{App, Arg, ArgMatches};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process;

#[derive(Debug, Clone, Copy)]
pub struct AppEnvironment {
    pub appname: &'static str,
    pub host: &'static str,
    pub port: i32,
    pub configure: &'static str,
    pub version: &'static str,
    pub prefix: &'static str,
    pub log: &'static str,
    pub log_rotate: i32,
    pub log_rotate_size: usize,
    pub pid_file: &'static str,
}

struct AppEnvironmentInfo {
    pub host: Option<String>,
    pub port: i32,
    pub configure: Option<String>,
    pub prefix: Option<String>,
    pub log: Option<String>,
    pub log_rotate: i32,
    pub log_rotate_size: usize,
    pub pid_file: Option<String>,
}

static mut APP_ENV_INFO_STORE: AppEnvironmentInfo = AppEnvironmentInfo {
    host: None,
    port: 12018,
    configure: None,
    prefix: None,
    log: None,
    log_rotate: 8,
    log_rotate_size: 2097152,
    pid_file: None,
};

/// Build a clap application parameterized by usage strings.
pub fn app() -> AppEnvironment {
    let app = App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .max_term_width(100)
        .arg(
            Arg::with_name("version")
                .short("v")
                .long("version")
                .help("Show version"),
        )
        .arg(
            Arg::with_name("host")
                .short("H")
                .long("host")
                .value_name("HOST")
                .help("Set a bind host")
                .takes_value(true)
                .default_value("::"),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .takes_value(true)
                .help("Set a bind port"),
        )
        .arg(
            Arg::with_name("prefix")
                .short("P")
                .long("prefix")
                .value_name("PREFIX")
                .help("Set a url prefix for current service")
                .takes_value(true)
                .default_value("/"),
        )
        .arg(
            Arg::with_name("configure")
                .short("c")
                .long("conf")
                .value_name("CONFIGURE")
                .help("Set configure file")
                .require(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("LOG PATH")
                .help("Set log path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-rotate")
                .long("log-rotate")
                .value_name("LOG ROTATE")
                .help("Set log rotate")
                .takes_value(true)
                .default_value("8"),
        )
        .arg(
            Arg::with_name("log-rotate-size")
                .long("log-rotate-size")
                .value_name("LOG ROTATE SIZE")
                .help("Set log rotate size in bytes")
                .takes_value(true)
                .default_value("16777216"),
        )
        .arg(
            Arg::with_name("pid-file")
                .long("pid-file")
                .value_name("PID FILE")
                .help("Set path of pid file")
                .takes_value(true),
        );

    let matches: ArgMatches = app.get_matches();
    if matches.is_present("version") {
        println!("{}", crate_version!());
        process::exit(0);
    }

    unsafe {
        if let Some(mut x) = matches.values_of("host") {
            if let Some(val) = x.next() {
                APP_ENV_INFO_STORE.host = Some(String::from(val));
            }
        }

        if let Some(mut x) = matches.values_of("port") {
            if let Some(val) = x.next() {
                if let Ok(port) = val.parse::<i32>() {
                    APP_ENV_INFO_STORE.port = port;
                }
            }
        }

        if let Some(mut x) = matches.values_of("configure") {
            if let Some(val) = x.next() {
                APP_ENV_INFO_STORE.configure = Some(String::from(val));
            }
        }

        if let Some(mut x) = matches.values_of("prefix") {
            if let Some(val) = x.next() {
                let mut val_str = String::from(val);
                if !val_str.starts_with("/") {
                    val_str.insert(0, '/');
                }
                if !val_str.ends_with("/") {
                    val_str.push('/');
                }
                APP_ENV_INFO_STORE.prefix = Some(val_str);
            }
        }

        if let Some(mut x) = matches.values_of("log") {
            if let Some(val) = x.next() {
                APP_ENV_INFO_STORE.log = Some(String::from(val));
            }
        } else {
            APP_ENV_INFO_STORE.log = Some(format!("{}.log", crate_name!()));
        }

        if let Some(mut x) = matches.values_of("log-rotate") {
            if let Some(val) = x.next() {
                if let Ok(rotate) = val.parse::<i32>() {
                    APP_ENV_INFO_STORE.log_rotate = rotate;
                }
            }
        }

        if let Some(mut x) = matches.values_of("log-rotate-size") {
            if let Some(val) = x.next() {
                if let Ok(rotate) = val.parse::<usize>() {
                    APP_ENV_INFO_STORE.log_rotate_size = rotate;
                }
            }
        }

        if let Some(mut x) = matches.values_of("pid-file") {
            if let Some(val) = x.next() {
                APP_ENV_INFO_STORE.pid_file = Some(String::from(val));
            }
        } else {
            APP_ENV_INFO_STORE.pid_file = Some(format!("{}.pid", crate_name!()));
        }
    }

    let app = generate_app_env();

    // write pid
    write_pid_file(app.pid_file);

    app
}

fn write_pid_file(pid_file: &str) {
    // get & create base dir
    let file_path = Path::new(pid_file);
    if let Some(dir_path) = file_path.parent() {
        if !dir_path.as_os_str().is_empty() && (!dir_path.exists() || !dir_path.is_dir()) {
            match create_dir_all(dir_path) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Try to create pid file directory {:?} failed, {}",
                        dir_path, e
                    );
                    return;
                }
            }
        }
    }

    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    match options.open(pid_file) {
        Ok(mut file) => match file.write(format!("{}", process::id()).as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Try to write {} to pid file {} failed, {}",
                    process::id(),
                    pid_file,
                    e
                );
            }
        },
        Err(e) => {
            eprintln!("Try to open pid file {} failed, {}", pid_file, e);
        }
    }
}

fn generate_app_env() -> AppEnvironment {
    unsafe {
        AppEnvironment {
            appname: crate_name!(),
            host: if let Some(ref x) = APP_ENV_INFO_STORE.host {
                x.as_str()
            } else {
                "::"
            },
            port: APP_ENV_INFO_STORE.port,
            configure: if let Some(ref x) = APP_ENV_INFO_STORE.configure {
                x.as_str()
            } else {
                "conf.json"
            },
            version: crate_version!(),
            prefix: if let Some(ref x) = APP_ENV_INFO_STORE.prefix {
                x.as_str()
            } else {
                "/"
            },
            log: if let Some(ref x) = APP_ENV_INFO_STORE.log {
                x.as_str()
            } else {
                "server.log"
            },
            log_rotate: APP_ENV_INFO_STORE.log_rotate,
            log_rotate_size: APP_ENV_INFO_STORE.log_rotate_size,
            pid_file: if let Some(ref x) = APP_ENV_INFO_STORE.pid_file {
                x.as_str()
            } else {
                "server.pid"
            },
        }
    }
}

impl AppEnvironment {
    fn get_info(&self, is_html: bool) -> String {
        let title = format!(
            "{0} {1} Listen on {2}:{3} {4}",
            self.appname, self.version, self.host, self.port
        );

        let header = if is_html {
            format!(
                "<h3>{}</h3><table><tr><th>Option</th><th>Value</th></tr>",
                title
            )
        } else {
            format!("# {}", title)
        };

        let mut prefix_str = String::from(self.prefix);
        prefix_str.pop();
        let tail = if is_html { "</table>" } else { "" };
        let row_begin = if is_html { "<tr><td>" } else { "" };
        let row_split = if is_html { "</td><td>" } else { ": " };
        let row_end = if is_html { "</td></tr>" } else { "" };
        format!(
            "{3}
{5}Wechat robot callback URL: {6}http://{0}:{1}{2}/<project name>{7}
{4}",
            self.host, self.port, prefix_str, header, tail, row_begin, row_split, row_end
        )
    }

    pub fn text_info(&self) -> String {
        self.get_info(false)
    }

    pub fn html_info(&self, user: &str) -> String {
        self.get_info(true)
    }
}
