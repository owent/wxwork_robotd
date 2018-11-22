extern crate clap;
use clap::{App, Arg, ArgMatches};
use serde_json;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process;
use std::rc::Rc;
use std::sync::Arc;

use wxwork_robot;
use wxwork_robot::command::{WXWorkCommandList, WXWorkCommandMatch, WXWorkCommandPtr};
use wxwork_robot::project::WXWorkProject;

#[derive(Debug, Clone)]
pub struct AppConfigure {
    pub task_timeout: u64,
    pub hosts: Option<Vec<String>>,
    pub workers: usize,
    pub backlog: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct AppEnvironment {
    pub appname: &'static str,
    pub configure: &'static str,
    pub version: &'static str,
    pub prefix: &'static str,
    pub debug: bool,
    pub log: &'static str,
    pub log_rotate: i32,
    pub log_rotate_size: usize,
    pub pid_file: &'static str,
    pub conf: &'static AppConfigure,
}

struct AppEnvironmentInfo {
    init: bool,
    pub debug: bool,
    pub configure: Option<String>,
    pub prefix: Option<String>,
    pub log: Option<String>,
    pub log_rotate: i32,
    pub log_rotate_size: usize,
    pub pid_file: Option<String>,
    pub projects: Option<wxwork_robot::WXWorkProjectSetShared>,
    pub conf: AppConfigure,
}

static mut APP_ENV_INFO_STORE: AppEnvironmentInfo = AppEnvironmentInfo {
    init: false,
    debug: false,
    configure: None,
    prefix: None,
    log: None,
    log_rotate: 8,
    log_rotate_size: 2097152,
    pid_file: None,
    projects: None,
    conf: AppConfigure {
        task_timeout: 5000,
        hosts: None,
        workers: 8,
        backlog: 256,
    },
};

/// Build a clap application parameterized by usage strings.
pub fn app() -> AppEnvironment {
    unsafe {
        if APP_ENV_INFO_STORE.init {
            return generate_app_env();
        }
    }

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
        ).arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("Show debug log"),
        ).arg(
            Arg::with_name("prefix")
                .short("P")
                .long("prefix")
                .value_name("PREFIX")
                .help("Set a url prefix for current service")
                .takes_value(true)
                .default_value("/"),
        ).arg(
            Arg::with_name("configure")
                .short("c")
                .long("conf")
                .value_name("CONFIGURE")
                .help("Set configure file")
                .required(true)
                .takes_value(true),
        ).arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("LOG PATH")
                .help("Set log path")
                .takes_value(true),
        ).arg(
            Arg::with_name("log-rotate")
                .long("log-rotate")
                .value_name("LOG ROTATE")
                .help("Set log rotate")
                .takes_value(true)
                .default_value("8"),
        ).arg(
            Arg::with_name("log-rotate-size")
                .long("log-rotate-size")
                .value_name("LOG ROTATE SIZE")
                .help("Set log rotate size in bytes")
                .takes_value(true),
        ).arg(
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
        if matches.is_present("debug") {
            APP_ENV_INFO_STORE.debug = true;
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

        APP_ENV_INFO_STORE.init = true;
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

pub fn app_conf() -> &'static AppConfigure {
    let ret;
    unsafe {
        ret = &APP_ENV_INFO_STORE.conf;
    }

    ret
}

fn generate_app_env() -> AppEnvironment {
    unsafe {
        AppEnvironment {
            appname: crate_name!(),
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
            debug: APP_ENV_INFO_STORE.debug,
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
            conf: &APP_ENV_INFO_STORE.conf,
        }
    }
}

impl AppEnvironment {
    fn get_info(&self, is_html: bool) -> String {
        let mut title = format!("{0} {1} Listen on", self.appname, self.version);
        for v in self.get_hosts() {
            title += format!(" \"{0}\"", v).as_str();
        }
        title += format!(" with prefix {0}", self.prefix).as_str();

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
        let mut row_host = String::from("");
        for v in self.get_hosts() {
            if let Ok(saddr_iter) = v.to_socket_addrs() {
                for saddr in saddr_iter {
                    if saddr.is_ipv4() {
                        row_host +=
                            format!(
                            "{3}Wechat robot callback URL: {4}http://{0}:{1}{2}/<project name>{5}",
                            saddr.ip(), saddr.port(), prefix_str, row_begin, row_split, row_end
                        ).as_str();
                        if saddr.ip().is_unspecified() {
                            row_host +=
                                format!(
                                "{3}Wechat robot callback URL: {4}http://{0}:{1}{2}/<project name>{5}",
                                "127.0.0.1", saddr.port(), prefix_str, row_begin, row_split, row_end
                            ).as_str();
                        }
                    } else if saddr.is_ipv6() {
                        row_host += format!(
                            "{3}Wechat robot callback URL: {4}http://[{0}]:{1}{2}/<project name>{5}",
                            saddr.ip(), saddr.port(), prefix_str, row_begin, row_split, row_end
                        ).as_str();
                        if saddr.ip().is_unspecified() {
                            row_host +=
                                format!(
                                "{3}Wechat robot callback URL: {4}http://{0}:{1}{2}/<project name>{5}",
                                "::", saddr.port(), prefix_str, row_begin, row_split, row_end
                            ).as_str();
                        }
                    }
                }
            }
        }
        format!("{0}\r\n{1}\r\n{2}", header, row_host, tail)
    }

    pub fn text_info(&self) -> String {
        self.get_info(false)
    }

    pub fn html_info(&self) -> String {
        self.get_info(true)
    }

    pub fn get_hosts(&self) -> Vec<String> {
        let ret: Vec<String>;
        unsafe {
            ret = if let Some(ref x) = APP_ENV_INFO_STORE.conf.hosts {
                x.clone()
            } else {
                Vec::new()
            };
        }

        ret
    }

    pub fn get_projects(&self) -> Option<wxwork_robot::WXWorkProjectSetShared> {
        let ret: Option<wxwork_robot::WXWorkProjectSetShared>;
        unsafe {
            ret = if let Some(ref x) = APP_ENV_INFO_STORE.projects {
                Some(x.clone())
            } else {
                None
            };
        }

        ret
    }

    pub fn set_projects(&self, val: wxwork_robot::WXWorkProjectSetShared) {
        {
            if let Ok(x) = val.lock() {
                let ref_x: &wxwork_robot::WXWorkProjectSet = &*x;
                for (k, _) in ref_x.projs.iter() {
                    info!("load project \"{}\" success", k);
                }

                for cmd in ref_x.cmds.iter() {
                    info!("load global command \"{}\" success", cmd.name());
                }
            }
        }

        unsafe {
            APP_ENV_INFO_STORE.projects = Some(val);
        }
    }

    pub fn get_project(&self, name: &str) -> Option<Arc<WXWorkProject>> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                if let Some(found_proj) = (*x).projs.get(name) {
                    return Some(found_proj.clone());
                }
            }
        }

        None
    }

    pub fn get_global_command(
        &self,
        message: &str,
    ) -> Option<(WXWorkCommandPtr, WXWorkCommandMatch)> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                return WXWorkProject::try_capture_commands(&(*x).cmds, message);
            }
        }

        None
    }

    /// Get global command list.
    ///
    /// **This is a high cost API**
    pub fn get_global_command_list(&self) -> Rc<WXWorkCommandList> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                return (*x).cmds.clone();
            }
        }

        Rc::new(Vec::new())
    }

    pub fn reload(&mut self) -> bool {
        let mut options = OpenOptions::new();
        options.read(true).write(false);
        match options.open(self.configure) {
            Ok(f) => {
                if let Ok(conf) = serde_json::from_reader(f) {
                    let conf_json: serde_json::Value = conf;
                    self.reload_app_conf(&conf_json);
                    if let Some(x) = wxwork_robot::build_project_set_shared(&conf_json) {
                        self.set_projects(x);
                    } else {
                        error!(
                            "Build project set from configure file {} failed",
                            self.configure
                        );
                        return false;
                    }
                } else {
                    error!("Parse configure file {} as json failed", self.configure);
                    return false;
                }
            }
            Err(e) => {
                error!("Open configure file {} failed, {:?}", self.configure, e);
                return false;
            }
        }

        true
    }

    fn reload_app_conf(&mut self, conf_json: &serde_json::Value) {
        let kvs = if let Some(x) = conf_json.as_object() {
            x
        } else {
            return;
        };

        if let Some(x) = kvs.get("taskTimeout") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.task_timeout = v;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("workers") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.workers = v as usize;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("backlog") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.backlog = v as i32;
                    }
                }
            }
        }

        {
            let mut hosts = Vec::new();
            if let Some(x) = kvs.get("listen") {
                if let Some(arr) = x.as_array() {
                    for v in arr {
                        if let Some(vh) = v.as_str() {
                            hosts.push(String::from(vh));
                        }
                    }
                } else if let Some(v) = x.as_str() {
                    hosts.push(String::from(v));
                }
            }

            if hosts.len() == 0 {
                hosts.push(String::from("0.0.0.0:12019"));
                hosts.push(String::from(":::12019"));
            }

            unsafe {
                APP_ENV_INFO_STORE.conf.hosts = Some(hosts);
            }
        }
    }
}
