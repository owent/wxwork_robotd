use actix_web::{HttpRequest, HttpResponse};
use futures::future::{ok as future_ok};

use super::{AppEnvironment, HttpResponseFuture};

pub fn dispatch_default_index(app: AppEnvironment, _: HttpRequest) -> HttpResponseFuture {
        let output = format!(
                "<!DOCTYPE html>
<html><head>
<meta charset=\"utf-8\" />
<style type=\"text/css\">
table {{ border-collapse: collapse; border: .05rem solid #d3d3d3; }}
table th, table td {{ border: 1px solid black; padding: 0.5rem; }}
</style>
<title>{}</title></head>
<body>{}</body></html>",
                app.appname,
                app.html_info()
        );

        Box::new(future_ok(HttpResponse::Forbidden()
                .content_type("text/html")
                .body(output)))
}

// impl<'r, S> FnOnce<(&'r HttpRequest,)> for AppDispatchDefault {
//     type Output = HttpResponseFuture;
//     extern "rust-call" fn call_once(self, args: (&'r HttpRequest,)) -> Self::Output {
//         self.handle(args.0)
//     }
// }
//
// impl<'r, S> FnMut<(&'r HttpRequest,)> for AppDispatchDefault {
//     extern "rust-call" fn call_mut(&mut self, args: (&'r HttpRequest,)) -> HttpResponseFuture {
//         self.handle(args.0)
//     }
// }
//
// impl<'r, S> Fn<(&'r HttpRequest,)> for AppDispatchDefault {
//     extern "rust-call" fn call(&self, args: (&'r HttpRequest,)) -> HttpResponseFuture {
//         self.handle(args.0)
//     }
// }
//
