use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use crate::clap::{Arg, ArgAction, ArgMatches};

use super::wxwork_robot::command::{WxWorkCommandList, WxWorkCommandMatch, WxWorkCommandPtr};
use super::wxwork_robot::project::WxWorkProject;
use super::wxwork_robot::{build_project_set_shared, WxWorkProjectSet, WxWorkProjectSetShared};

#[derive(Debug, Clone)]
pub struct AppConfigure {
    pub task_timeout: u64,
    pub hosts: Option<Vec<String>>,
    pub workers: usize,
    pub backlog: u32,
    pub keep_alive: u64,
    pub client_timeout: u64,
    pub client_shutdown: u64,
    pub max_connection_per_worker: usize,
    pub max_concurrent_rate_per_worker: usize,
    pub payload_size_limit: usize,
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
    pub projects: Option<WxWorkProjectSetShared>,
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
        keep_alive: 5,
        client_timeout: 5000,
        client_shutdown: 5000,
        max_connection_per_worker: 20480,
        max_concurrent_rate_per_worker: 256,
        payload_size_limit: 262144, // 256KB
    },
};

fn unwraper_flag<S>(matches: &ArgMatches, name: S) -> bool
where
    S: AsRef<str>,
{
    if let Ok(Some(x)) = matches.try_get_one::<bool>(name.as_ref()) {
        return *x;
    }

    false
}

pub trait OptionValueWrapper<T> {
    fn pick(input: &str) -> Option<T>;
}

impl<T> OptionValueWrapper<T> for T
where
    T: FromStr,
{
    fn pick(input: &str) -> Option<Self> {
        if let Ok(v) = input.parse::<T>() {
            Some(v)
        } else {
            None
        }
    }
}

fn unwraper_option<T, S>(matches: &ArgMatches, name: S) -> Option<T>
where
    T: OptionValueWrapper<T>,
    S: AsRef<str>,
{
    if let Ok(Some(x)) = matches.try_get_raw(name.as_ref()) {
        for val in x {
            if let Some(str_val) = val.to_str() {
                return T::pick(str_val);
            }
        }
    }

    None
}

/// Build a clap application parameterized by usage strings.
pub fn app() -> AppEnvironment {
    unsafe {
        if APP_ENV_INFO_STORE.init {
            return generate_app_env();
        }
    }

    let matches = command!();

    let app = matches
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .max_term_width(120)
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::SetTrue)
                .help("Show version"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Show debug log"),
        )
        .arg(
            Arg::new("prefix")
                .short('P')
                .long("prefix")
                .value_name("PREFIX")
                .help("Set a url prefix for current service")
                .default_value("/"),
        )
        .arg(
            Arg::new("configure")
                .short('c')
                .long("conf")
                .value_name("CONFIGURE")
                .help("Set configure file")
                .required(true),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .value_name("LOG PATH")
                .help("Set log path"),
        )
        .arg(
            Arg::new("log-rotate")
                .long("log-rotate")
                .value_name("LOG ROTATE")
                .help("Set log rotate")
                .default_value("8"),
        )
        .arg(
            Arg::new("log-rotate-size")
                .long("log-rotate-size")
                .value_name("LOG ROTATE SIZE")
                .help("Set log rotate size in bytes"),
        )
        .arg(
            Arg::new("pid-file")
                .long("pid-file")
                .value_name("PID FILE")
                .help("Set path of pid file"),
        );

    let matches: ArgMatches = app.get_matches();
    if unwraper_flag(&matches, "version") {
        println!("{}", crate_version!());
        process::exit(0);
    }

    unsafe {
        if unwraper_flag(&matches, "debug") {
            APP_ENV_INFO_STORE.debug = true;
        }

        if let Some(val) = unwraper_option(&matches, "configure") {
            APP_ENV_INFO_STORE.configure = Some(val);
        }

        if let Some(mut val_str) = unwraper_option::<String, _>(&matches, "prefix") {
            if !val_str.starts_with('/') {
                val_str.insert(0, '/');
            }
            if !val_str.ends_with('/') {
                val_str.push('/');
            }
            APP_ENV_INFO_STORE.prefix = Some(val_str);
        }

        if let Some(val) = unwraper_option(&matches, "log") {
            APP_ENV_INFO_STORE.log = Some(val);
        } else {
            APP_ENV_INFO_STORE.log = Some(format!("{}.log", crate_name!()));
        }

        if let Some(rotate) = unwraper_option(&matches, "log-rotate") {
            APP_ENV_INFO_STORE.log_rotate = rotate;
        }

        if let Some(rotate_size) = unwraper_option(&matches, "log-rotate-size") {
            APP_ENV_INFO_STORE.log_rotate_size = rotate_size;
        }

        if let Some(val) = unwraper_option(&matches, "pid-file") {
            APP_ENV_INFO_STORE.pid_file = Some(val);
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
        let row_end = if is_html { "</td></tr>" } else { "\n" };
        let mut row_host = String::from("");
        for v in self.get_hosts() {
            if let Ok(saddr_iter) = v.to_socket_addrs() {
                for saddr in saddr_iter {
                    if saddr.is_ipv4() {
                        row_host +=
                            format!(
                            "{3}Wechat robot callback URL: {4}http://{0}:{1}{2}/<project name>{5}",
                            saddr.ip(), saddr.port(), prefix_str, row_begin, row_split, row_end
                        )
                            .as_str();
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

    pub fn get_projects(&self) -> Option<WxWorkProjectSetShared> {
        let ret: Option<WxWorkProjectSetShared>;
        unsafe {
            ret = APP_ENV_INFO_STORE.projects.as_ref().cloned();
        }

        ret
    }

    pub fn set_projects(&self, val: WxWorkProjectSetShared) {
        {
            if let Ok(x) = val.lock() {
                let ref_x: &WxWorkProjectSet = &x;
                for (k, _) in ref_x.projs.iter() {
                    info!("load project \"{}\" success", k);
                }

                for cmd in ref_x.cmds.iter() {
                    info!("load global command \"{}\" success", cmd.name());
                }

                for cmd in ref_x.events.iter() {
                    info!("load global event \"{}\" success", cmd.name());
                }
            }
        }

        unsafe {
            APP_ENV_INFO_STORE.projects = Some(val);
        }
    }

    pub fn get_project(&self, name: &str) -> Option<Arc<WxWorkProject>> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                if let Some(found_proj) = x.projs.get(name) {
                    return Some(found_proj.clone());
                }
            }
        }

        None
    }

    pub fn get_global_command(
        &self,
        message: &str,
        allow_hidden: bool,
    ) -> Option<(WxWorkCommandPtr, WxWorkCommandMatch)> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                return WxWorkProject::try_capture_commands(&x.cmds, message, allow_hidden);
            }
        }

        None
    }

    pub fn get_global_event(
        &self,
        message: &str,
        allow_hidden: bool,
    ) -> Option<(WxWorkCommandPtr, WxWorkCommandMatch)> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                return WxWorkProject::try_capture_commands(&x.events, message, allow_hidden);
            }
        }

        None
    }

    /// Get global command list.
    ///
    /// **This is a high cost API**
    pub fn get_global_command_list(&self) -> Rc<WxWorkCommandList> {
        if let Some(projs) = self.get_projects() {
            if let Ok(x) = projs.lock() {
                return x.cmds.clone();
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
                    if let Some(x) = build_project_set_shared(&conf_json) {
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

        if let Some(x) = kvs.get("task_timeout") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.task_timeout = v;
                    }
                }
            }
        } else if let Some(x) = kvs.get("taskTimeout") {
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
                        APP_ENV_INFO_STORE.conf.backlog = v as u32;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("keep_alive") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.keep_alive = v;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("client_timeout") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.client_timeout = v;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("client_shutdown") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.client_shutdown = v;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("max_connection_per_worker") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.max_connection_per_worker = v as usize;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("max_concurrent_rate_per_worker") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.max_concurrent_rate_per_worker = v as usize;
                    }
                }
            }
        }

        if let Some(x) = kvs.get("payload_size_limit") {
            if let Some(v) = x.as_u64() {
                if v > 0 {
                    unsafe {
                        APP_ENV_INFO_STORE.conf.payload_size_limit = v as usize;
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

            if hosts.is_empty() {
                hosts.push(String::from("0.0.0.0:12019"));
                hosts.push(String::from(":::12019"));
            }

            unsafe {
                APP_ENV_INFO_STORE.conf.hosts = Some(hosts);
            }
        }
    }
}
