use actix_web::{AsyncResponder, HttpRequest, HttpResponse};
use futures::future::result;

use super::{AppEnvironment, HttpResponseFuture};

pub fn dispatch_default_index<S>(app: AppEnvironment, _req: &HttpRequest<S>) -> HttpResponseFuture {
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

        result(Ok(HttpResponse::Forbidden()
                .content_type("text/html")
                .body(output))).responder()
}

// impl<'r, S> FnOnce<(&'r HttpRequest<S>,)> for AppDispatchDefault {
//     type Output = HttpResponseFuture;
//     extern "rust-call" fn call_once(self, args: (&'r HttpRequest<S>,)) -> Self::Output {
//         self.handle(args.0)
//     }
// }
//
// impl<'r, S> FnMut<(&'r HttpRequest<S>,)> for AppDispatchDefault {
//     extern "rust-call" fn call_mut(&mut self, args: (&'r HttpRequest<S>,)) -> HttpResponseFuture {
//         self.handle(args.0)
//     }
// }
//
// impl<'r, S> Fn<(&'r HttpRequest<S>,)> for AppDispatchDefault {
//     extern "rust-call" fn call(&self, args: (&'r HttpRequest<S>,)) -> HttpResponseFuture {
//         self.handle(args.0)
//     }
// }
//
