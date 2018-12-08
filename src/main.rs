// When the `system-alloc` feature is used, use the System Allocator
#[cfg(feature = "system-alloc")]
use std::alloc::System;
#[cfg(feature = "system-alloc")]
#[global_allocator]
static GLOBAL: System = System;

// crates
#[macro_use]
extern crate clap;
extern crate actix_web;
extern crate futures;
#[macro_use]
extern crate log;
extern crate base64;
extern crate bytes;
extern crate handlebars;
extern crate hex;
extern crate quick_xml;
extern crate time;
#[macro_use]
extern crate serde_json;
extern crate openssl;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate tokio;
extern crate tokio_process;

// #[macro_use]
// extern crate json;

// import packages
// use std::sync::Arc;
use actix_web::{server, App};
use std::net::TcpListener;

mod app;
mod handles;
mod logger;
mod wxwork_robot;

fn main() {
    let mut app_env = app::app();
    if app_env.debug {
        if let Err(e) = logger::init_with_level(
            log::Level::Debug,
            app_env.log,
            app_env.log_rotate,
            app_env.log_rotate_size,
        ) {
            eprintln!("Setup debug log failed: {:?}.", e);
            return;
        }
    } else {
        if let Err(e) = logger::init(app_env.log, app_env.log_rotate, app_env.log_rotate_size) {
            eprintln!("Setup log failed: {:?}.", e);
            return;
        }
    }

    if !app_env.reload() {
        eprintln!("Load configure {} failed.", app_env.configure);
        return;
    }

    let run_info = app_env.text_info();
    let mut server = server::new(move || {
        let app = App::new();
        app_env.setup(app)
    });

    if app_env.debug {
        server = server.workers(1);
    } else {
        server = server.workers(app_env.conf.workers);
    }
    server = server.backlog(app_env.conf.backlog);

    // server = server.client_timeout(app_env.conf.task_timeout);
    let mut listened_count = 0;
    for ref host in app_env.get_hosts() {
        let listener = match TcpListener::bind(host.as_str()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "Listen address {} failed and ignore this address: {}",
                    host, e
                );
                error!(
                    "Listen address {} failed and ignore this address: {}",
                    host, e
                );
                continue;
            }
        };

        server = server.listen(listener);
        println!("listen on {} success", host);
        listened_count += 1;
    }

    if listened_count == 0 {
        return;
    }

    info!("{}", run_info);
    server.run();
}
