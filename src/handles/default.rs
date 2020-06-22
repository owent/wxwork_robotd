use actix_web::{HttpRequest, HttpResponse};

use super::super::app::AppEnvironment;

pub async fn dispatch_default_index(app: AppEnvironment, _: HttpRequest) -> HttpResponse {
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

        HttpResponse::Forbidden()
                .content_type("text/html")
                .body(output)
}
