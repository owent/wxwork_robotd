use actix_web::{FromRequest, HttpRequest, HttpResponse, web};
use futures::future::{ok as future_ok, Either, Future};
use futures::{Stream};
use std::sync::Arc;
use serde::Deserialize;

use super::{AppEnvironment, HttpResponseFuture};
use wxwork_robot::command_runtime;
use wxwork_robot::command_runtime::WXWorkCommandRuntime;
use wxwork_robot::error;
use wxwork_robot::message;

#[derive(Deserialize)]
pub struct WXWorkRobotVerifyMessage {
   msg_signature: String,
   timestamp: String,
   nonce: String,
   echostr: String,
}

#[derive(Deserialize)]
pub struct WXWorkRobotPostMessage {
   msg_signature: String,
   timestamp: String,
   nonce: String,
}

pub fn get_robot_project_name(_app: &AppEnvironment, req: &HttpRequest) -> Option<String> {
    let params = web::Path::<(String)>::extract(req);
    let project = if let Ok(project_name) = params {
        Some(project_name.into_inner())
    } else {
        None
    };

    project
}

enum WXWorkDispatchProcess {
    ErrorResponse(HttpResponse),
    // ERROR_MESSAGE(String),
    CommandRuntime(Arc<WXWorkCommandRuntime>),
}

fn make_robot_error_response_future(msg: &str) -> HttpResponseFuture {
    Box::new(future_ok(message::make_robot_error_response_content(msg)))
}

pub fn dispatch_robot_request(
    app: AppEnvironment,
    req: HttpRequest,
) -> HttpResponseFuture {
    let project_name = if let Some(x) = get_robot_project_name(&app, &req) {
        x
    } else {
        return make_robot_error_response_future("project not found");
    };

    if let Ok(x) = web::Query::<WXWorkRobotVerifyMessage>::from_query(req.query_string()) {
        let xv = x.into_inner();
        if !xv.echostr.is_empty() {
            return dispatch_robot_verify(app, project_name, xv);
        }
    } 
    
    
    if let Ok(x) = web::Query::<WXWorkRobotPostMessage>::from_query(req.query_string()) {
        return dispatch_robot_message(app, Arc::new(project_name), x.into_inner(), &req);
    } 
    
    make_robot_error_response_future("parameter error.")
}

fn dispatch_robot_verify(app: AppEnvironment, project_name: String, req_msg: WXWorkRobotVerifyMessage) -> HttpResponseFuture {
    // GET http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323&echostr=ENCRYPT_STR
    let proj_obj = if let Some(v) = app.get_project(project_name.as_str()) {
        v
    } else {
        return make_robot_error_response_future(
            format!("project \"{}\" not found", project_name).as_str(),
        );
    };

    if req_msg.msg_signature.is_empty() {
        return make_robot_error_response_future("msg_signature is required");
    };
    if req_msg.timestamp.is_empty() {
        return make_robot_error_response_future("timestamp is required");
    };
    if req_msg.nonce.is_empty() {
        return make_robot_error_response_future("nonce is required");
    };

    if !proj_obj.check_msg_signature(
        req_msg.msg_signature.as_str(),
        req_msg.timestamp.as_str(),
        req_msg.nonce.as_str(),
        req_msg.echostr.as_str(),
    ) {
        return make_robot_error_response_future(
            format!("project \"{}\" check msg_signature failed", project_name).as_str(),
        );
    }

    info!(
        "project \"{}\" check msg_signature and passed",
        project_name
    );

    let output = if let Ok(x) = proj_obj.decrypt_msg_raw_base64_content(req_msg.echostr.as_str()) {
        x
    } else {
        let err_msg = format!(
            "project \"{}\" try to decode \"{}\" failed",
            project_name, req_msg.echostr
        );
        debug!("{}", err_msg);
        return make_robot_error_response_future(err_msg.as_str());
    };

    Box::new(future_ok(
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(output.content),
    ))
}

fn dispatch_robot_message(
    app: AppEnvironment,
    project_name: Arc<String>,
    req_msg: WXWorkRobotPostMessage,
    req: &HttpRequest,
) -> HttpResponseFuture {
    // POST http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323
    if req_msg.msg_signature.is_empty() {
        return make_robot_error_response_future("msg_signature is required");
    };
    if req_msg.timestamp.is_empty() {
        return make_robot_error_response_future("timestamp is required");
    };
    if req_msg.nonce.is_empty() {
        return make_robot_error_response_future("nonce is required");
    };

    let project_name_for_err = project_name.clone();
    let project_name_for_run_fut = project_name.clone();

    let req_body = match web::Payload::extract(req) {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!(
                "project \"{}\" request extract error, {:?}",
                project_name_for_err, e
            );
            error!("{}", err_msg);
            return make_robot_error_response_future(err_msg.as_str());
        }
    };

    Box::new(
        // .limit(256 * 1024)
        req_body.map_err(move |e| {
            let err_msg = format!(
                "project \"{}\" request error, {:?}",
                project_name_for_err, e
            );
            error!("{}", err_msg);
            error::Error::StringErr(err_msg)
        })
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<web::BytesMut, error::Error>(body)
        })
        .and_then(move |bytes_mut: web::BytesMut| {
            let bytes = web::Bytes::from(bytes_mut);
            let proj_obj = if let Some(v) = app.get_project(project_name_for_run_fut.as_str()) {
                v
            } else {
                return Ok(WXWorkDispatchProcess::ErrorResponse(
                    message::make_robot_error_response_content(
                        format!("project \"{}\" not found", project_name_for_run_fut).as_str(),
                    ),
                ));
            };

            let encrypt_msg_b64 = if let Some(x) = message::get_msg_encrypt_from_bytes(bytes) {
                x
            } else {
                return Ok(WXWorkDispatchProcess::ErrorResponse(
                    message::make_robot_error_response_content(
                        format!(
                            "project \"{}\" can not decode message body",
                            project_name_for_run_fut
                        ).as_str(),
                    ),
                ));
            };

            if !proj_obj.check_msg_signature(
                req_msg.msg_signature.as_str(),
                req_msg.timestamp.as_str(),
                req_msg.nonce.as_str(),
                encrypt_msg_b64.as_str(),
            ) {
                return Ok(WXWorkDispatchProcess::ErrorResponse(
                    message::make_robot_error_response_content(
                        format!(
                            "project \"{}\" check msg_signature for message {} failed",
                            project_name_for_run_fut, encrypt_msg_b64
                        ).as_str(),
                    ),
                ));
            }

            debug!(
                "project \"{}\" check msg_signature for message {} and passed",
                project_name_for_run_fut, encrypt_msg_b64
            );

            let msg_dec =
                if let Ok(x) = proj_obj.decrypt_msg_raw_base64_content(encrypt_msg_b64.as_str()) {
                    x
                } else {
                    return Ok(WXWorkDispatchProcess::ErrorResponse(
                        message::make_robot_error_response_content(
                            format!(
                                "project \"{}\" decrypt message {} failed",
                                project_name_for_run_fut, encrypt_msg_b64
                            ).as_str(),
                        ),
                    ));
                };

            // 提取数据
            let msg_ntf = if let Some(x) = message::get_msg_from_str(msg_dec.content.as_str()) {
                x
            } else {
                return Ok(WXWorkDispatchProcess::ErrorResponse(
                    message::make_robot_error_response_content(
                        format!(
                            "project \"{}\" get message from {} failed",
                            project_name_for_run_fut, msg_dec.content
                        ).as_str(),
                    ),
                ));
            };

            // 查找匹配命令
            let (cmd_ptr, mut cmd_match_res, is_default_cmd) =
                if let Some((x, y)) = proj_obj.try_commands(&msg_ntf.content) {
                    // project 域内查找命令
                    (x, y, false)
                } else if let Some((x, y)) = app.get_global_command(&msg_ntf.content) {
                    // global 域内查找命令
                    (x, y, false)
                } else if let Some((x, y)) = proj_obj.try_commands("default") {
                    // project 域内查找默认命令
                    (x, y, true)
                } else if let Some((x, y)) = app.get_global_command("default") {
                    // global 域内查找默认命令
                    (x, y, true)
                } else {
                    return Ok(WXWorkDispatchProcess::ErrorResponse(
                        message::make_robot_error_response_content(
                            format!(
                                "project \"{}\" get command from {} failed",
                                project_name_for_run_fut, msg_ntf.content
                            ).as_str(),
                        ),
                    ));
                };

            if is_default_cmd {
                cmd_match_res.mut_json()["WXWORK_ROBOT_CMD"] =
                    serde_json::Value::String(msg_ntf.content.clone());
            }
            cmd_match_res.mut_json()["WXWORK_ROBOT_WEBHOOK_KEY"] =
                serde_json::Value::String(msg_ntf.web_hook_key.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_WEBHOOK_URL"] =
                serde_json::Value::String(msg_ntf.web_hook_url.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_MSG_FROM_USER_ID"] =
                serde_json::Value::String(msg_ntf.from.user_id.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_MSG_FROM_NAME"] =
                serde_json::Value::String(msg_ntf.from.name.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_MSG_FROM_ALIAS"] =
                serde_json::Value::String(msg_ntf.from.alias.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_MSG_ID"] =
                serde_json::Value::String(msg_ntf.msg_id.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_GET_CHAT_INFO_URL"] =
                serde_json::Value::String(msg_ntf.get_chat_info_url.clone());
            cmd_match_res.mut_json()["WXWORK_ROBOT_CHAT_ID"] =
                serde_json::Value::String(msg_ntf.chat_id.clone());

            // 填充模板参数json
            let template_vars = proj_obj.generate_template_vars(&cmd_match_res);
            let runtime = Arc::new(command_runtime::WXWorkCommandRuntime {
                proj: proj_obj.clone(),
                cmd: cmd_ptr,
                cmd_match: cmd_match_res,
                envs: template_vars,
                msg: msg_ntf,
            });

            // 执行命令，返回执行结果Future
            Ok(WXWorkDispatchProcess::CommandRuntime(runtime))
        }).and_then(
            move |next_process: WXWorkDispatchProcess| match next_process {
                WXWorkDispatchProcess::ErrorResponse(rsp) => Either::A(future_ok(rsp)),
                WXWorkDispatchProcess::CommandRuntime(runtime) => {
                    Either::B(command_runtime::run(runtime))
                }
            },
        ).then(move |final_res| match final_res {
            Ok(x) => {
                debug!("project \"{}\" response {:?}", project_name, x);
                future_ok(x)
            }
            Err(e) => {
                let err_msg = format!("project \"{}\" run command error, {:?}", project_name, e);
                error!("{}", err_msg);

                if let Some(v) = app.get_project(project_name.as_str()) {
                    future_ok(v.make_error_response(err_msg))
                } else {
                    future_ok(message::make_robot_error_response(err_msg))
                }
            }
        }))
}
