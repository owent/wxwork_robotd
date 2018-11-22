use futures::future::Future;

use actix_web::{middleware::Logger, App, Error, HttpResponse};

use app::AppEnvironment;

mod default;
mod robot;

pub type HttpResponseFuture = Box<Future<Item = HttpResponse, Error = Error>>;

impl AppEnvironment {
    pub fn setup(&self, app: App) -> App {
        let mut mut_app = app;

        mut_app = mut_app.middleware(Logger::new(
            "[ACCESS] %a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i %{Content-Type}i\" %T",
        ));

        // ====== register for index ======
        let mut reg_move = self.clone();
        mut_app = mut_app.resource(format!("{}", self.prefix).as_str(), move |r| {
            r.route()
                .a(move |req| default::dispatch_default_index(reg_move, req))
        });

        // ====== register for project ======
        reg_move = self.clone();
        mut_app = mut_app.resource(format!("{}{{project}}/", self.prefix).as_str(), move |r| {
            r.route()
                .a(move |req| robot::dispatch_robot_request(reg_move, req))
        });

        mut_app
    }
}
