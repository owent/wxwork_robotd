use futures::future::Future;

use actix_web::{middleware::Logger, App, Error, HttpResponse};

use app::AppEnvironment;

mod default;
mod idea;
mod key_sign;

pub type HttpResponseFuture = Box<Future<Item = HttpResponse, Error = Error>>;

impl AppEnvironment {
    pub fn setup(&self, app: App) -> App {
        let mut mut_app = app;

        mut_app = mut_app.middleware(Logger::new(
            "[ACCESS] %a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T",
        ));

        // ====== register for index ======
        let mut reg_move = self.clone();
        mut_app = mut_app.resource(format!("{}", self.prefix).as_str(), move |r| {
            r.route()
                .a(move |req| default::dispatch_default_index(reg_move, req))
        });
        reg_move = self.clone();
        mut_app = mut_app.resource(format!("{}{{username}}/", self.prefix).as_str(), move |r| {
            r.route()
                .a(move |req| default::dispatch_default_index(reg_move, req))
        });

        // ====== register for idea ======
        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}rpc/ping.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_ping(reg_move, req))
            },
        );
        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}{{username}}/rpc/ping.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_ping(reg_move, req))
            },
        );

        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}rpc/obtainTicket.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_obtain_ticket(reg_move, req))
            },
        );
        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}{{username}}/rpc/obtainTicket.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_obtain_ticket(reg_move, req))
            },
        );

        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}rpc/releaseTicket.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_release_ticket(reg_move, req))
            },
        );
        reg_move = self.clone();
        mut_app = mut_app.resource(
            format!("{}{{username}}/rpc/releaseTicket.action", self.prefix).as_str(),
            move |r| {
                r.route()
                    .a(move |req| idea::dispatch_idea_release_ticket(reg_move, req))
            },
        );

        // ====== register for jrebel ======

        mut_app
    }
}
