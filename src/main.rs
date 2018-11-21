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
extern crate hex;
extern crate openssl;
extern crate time;

// #[macro_use]
// extern crate json;

// import packages
// use std::sync::Arc;
use actix_web::{server, App};

mod app;
mod handles;
mod logger;

fn main() {
    let app_env = app::app();
    if let Err(e) = logger::init(app_env.log, app_env.log_rotate, app_env.log_rotate_size) {
        eprintln!("Setup log failed: {:?}.", e);
    }

    let run_info = app_env.text_info();
    let server = server::new(move || {
        let app = App::new();
        app_env.setup(app)
    }).bind(format!("{}:{}", app_env.host, app_env.port));

    match server {
        Ok(svr) => {
            println!("{}", run_info);
            info!("{}", run_info);
            svr.run();
        }

        Err(e) => {
            eprintln!("{}", e);
            error!("{}", e);
        }
    }
}
