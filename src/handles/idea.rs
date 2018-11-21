use actix_web::{AsyncResponder, FromRequest, HttpRequest, HttpResponse, Path};
use futures::future::result;
use hex;

use super::{AppEnvironment, HttpResponseFuture};
use handles::key_sign;

pub fn get_idea_username<S>(app: &AppEnvironment, req: &HttpRequest<S>) -> String {
    let params = Path::<(String)>::extract(req);
    let username = if let Ok(path) = params {
        path.into_inner()
    } else {
        String::from(app.username)
    };

    username
}

fn dispatch_idea_response_ok(rsp_type: &str, salt: &str) -> String {
    let xml_content = format!(
        "<{0}><message></message><responseCode>OK</responseCode><salt>{1}</salt></{0}>",
        rsp_type, salt
    );

    let xml_sig = match key_sign::sign(xml_content.as_bytes()) {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => String::from("sign failed"),
    };

    format!("<!-- {0} -->\n{1}", xml_sig, xml_content)
}

pub fn dispatch_idea_ping<S>(_app: AppEnvironment, req: &HttpRequest<S>) -> HttpResponseFuture {
    let query_params = req.query();
    let salt = if let Some(v) = query_params.get("salt") {
        v.clone()
    } else {
        return result(Ok(HttpResponse::Forbidden()
            .content_type("text/html; charset=utf-8")
            .body("")))
            .responder();
    };

    result(Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(dispatch_idea_response_ok(
            "PingResponse",
            salt.as_str(),
        )))).responder()
}

pub fn dispatch_idea_obtain_ticket<S>(
    app: AppEnvironment,
    req: &HttpRequest<S>,
) -> HttpResponseFuture {
    let prolongation_period = "607875500";

    let query_params = req.query();
    let salt = if let Some(v) = query_params.get("salt") {
        v.clone()
    } else {
        return result(Ok(HttpResponse::Forbidden()
            .content_type("text/html; charset=utf-8")
            .body("")))
            .responder();
    };

    let username = if let Some(v) = query_params.get("userName") {
        v.clone()
    } else {
        get_idea_username(&app, req)
    };

    let xml_content = format!(
        "<ObtainTicketResponse><message></message><prolongationPeriod>{0}</prolongationPeriod><responseCode>OK</responseCode><salt>{1}</salt><ticketId>1</ticketId><ticketProperties>licensee={2}\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>",
        prolongation_period, salt, username
    );

    let xml_sig = match key_sign::sign(xml_content.as_bytes()) {
        Ok(bytes) => String::from(hex::encode(bytes)),
        Err(_) => String::from("sign failed"),
    };

    let body_content = format!("<!-- {0} -->\n{1}", xml_sig, xml_content);
    info!("[IDEA]: allocate license for {0}", username);

    result(Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body_content)))
        .responder()
}

pub fn dispatch_idea_release_ticket<S>(
    _app: AppEnvironment,
    req: &HttpRequest<S>,
) -> HttpResponseFuture {
    let query_params = req.query();
    let salt = if let Some(v) = query_params.get("salt") {
        v.clone()
    } else {
        return result(Ok(HttpResponse::Forbidden()
            .content_type("text/html; charset=utf-8")
            .body("")))
            .responder();
    };

    result(Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(dispatch_idea_response_ok(
            "ReleaseTicketResponse",
            salt.as_str(),
        )))).responder()
}
