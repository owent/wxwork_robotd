use futures::future::Future;

use actix_web::{Error, HttpResponse};

pub mod default;
pub mod robot;

pub type HttpResponseFuture = Box<Future<Item = HttpResponse, Error = Error>>;
use app::AppEnvironment;
