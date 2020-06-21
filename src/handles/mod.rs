use futures::future::Future;

use actix_web::{Error, HttpResponse};

pub mod default;
pub mod robot;

use app::AppEnvironment;
