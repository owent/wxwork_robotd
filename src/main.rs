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
#[macro_use]
extern crate actix_rt;
extern crate futures;
#[macro_use]
extern crate log;
extern crate bytes;
extern crate handlebars;
extern crate hex;
extern crate quick_xml;
extern crate serde;
extern crate chrono;
#[macro_use]
extern crate serde_json;
extern crate openssl;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate tokio;

// #[macro_use]
// extern crate json;

// import packages
// use std::sync::Arc;
use actix_web::{middleware::Logger, web, App, HttpServer, Route};
use std::io;
use std::net::TcpListener;
use std::process;

mod app;
mod handles;
mod logger;
mod wxwork_robot;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    let mut app_env = app::app();
    if app_env.debug {
        if let Err(e) = logger::init_with_level(
            log::Level::Debug,
            app_env.log,
            app_env.log_rotate,
            app_env.log_rotate_size,
        ) {
            eprintln!("Setup debug log failed: {:?}.", e);
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    } else {
        if let Err(e) = logger::init(app_env.log, app_env.log_rotate, app_env.log_rotate_size) {
            eprintln!("Setup log failed: {:?}.", e);
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    }

    if !app_env.reload() {
        eprintln!("Load configure {} failed.", app_env.configure);
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }

    let run_info = app_env.text_info();
    let mut server = HttpServer::new(move || {
        let app = App::new().wrap(Logger::new(
            "[ACCESS] %a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i %{Content-Type}i\" %T",
        ));
        let reg_move_default = app_env.clone();
        let reg_move_robot = app_env.clone();

        app
            // ====== register for index ======
            .service(
                web::resource(format!("{}", app_env.prefix).as_str())
                    .data(web::PayloadConfig::default().limit(app_env.conf.payload_size_limit))
                    .to(move |req| handles::default::dispatch_default_index(reg_move_default, req)),
            )
            // ====== register for project ======
            .service(
                web::resource(format!("{}{{project}}/", app_env.prefix).as_str())
                    .data(web::PayloadConfig::default().limit(app_env.conf.payload_size_limit))
                    .to(move |req, body| {
                        handles::robot::dispatch_robot_request(reg_move_robot, req, body)
                    }),
            )
        // app_env.setup(app)
    });

    if app_env.debug {
        server = server.workers(1);
    } else {
        server = server.workers(app_env.conf.workers);
    }
    server = server
        .backlog(app_env.conf.backlog)
        .maxconn(app_env.conf.max_connection_per_worker)
        .maxconnrate(app_env.conf.max_concurrent_rate_per_worker)
        .keep_alive(app_env.conf.keep_alive)
        .client_timeout(app_env.conf.client_timeout)
        .client_shutdown(app_env.conf.client_shutdown);

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

        server = match server.listen(listener) {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "Bind address {} success but listen failed and ignore this address: {}",
                    host, e
                );
                error!(
                    "Bind address {} success but listen failed and ignore this address: {}",
                    host, e
                );
                return Err(e);
            }
        };

        println!("listen on {} success", host);
        listened_count += 1;
    }

    if listened_count == 0 {
        return Ok(());
    }

    info!("{}", run_info);
    let ret = server.run().await;
    if let Err(ref e) = ret {
        eprintln!("Start robotd service failed: {}", e);
        error!("Start robotd service failed: {}", e);
    }

    ret
}
