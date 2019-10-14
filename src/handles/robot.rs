use actix_web::{web, FromRequest, HttpRequest, HttpResponse};
use futures::future::{ok as future_ok, Future};
use serde::Deserialize;
use std::sync::Arc;

use super::{AppEnvironment, HttpResponseFuture};
use wxwork_robot::command_runtime;
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

fn make_robot_error_response_future(msg: &str) -> HttpResponseFuture {
    Box::new(future_ok(message::make_robot_error_response_content(msg)))
}

pub fn dispatch_robot_request(
    app: AppEnvironment,
    req: HttpRequest,
    body: web::Bytes,
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
        return dispatch_robot_message(app, Arc::new(project_name), x.into_inner(), body);
    }
    make_robot_error_response_future("parameter error.")
}

fn dispatch_robot_verify(
    app: AppEnvironment,
    project_name: String,
    req_msg: WXWorkRobotVerifyMessage,
) -> HttpResponseFuture {
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

// fn dispatch_robot_message_with_http_req(
//     app: AppEnvironment,
//     project_name: Arc<String>,
//     req_msg: WXWorkRobotPostMessage,
//     req: HttpRequest,
// ) -> HttpResponseFuture {
//     // Box::new(
//     //     web::Bytes::extract(req).then(move |extract_res| match extract_res {
//     //         Ok(x) => dispatch_robot_message(app, project_name, req_msg, x),
//     //         Err(e) => {
//     //             let err_msg = format!(
//     //                 "project \"{}\" request extract payload error, {:?}",
//     //                 project_name, e
//     //             );
//     //             error!("{}", err_msg);
//     //             make_robot_error_response_future(err_msg.as_str())
//     //         }
//     //     }),
//     // )
//     // match req.take_payload() {
//     //     Ok(x) => dispatch_robot_message_with_payload(app, project_name, req_msg, req.take_payload()),
//     //     Err(e) => {
//     //         let err_msg = format!(
//     //             "project \"{}\" request extract payload error, {:?}",
//     //             project_name, e
//     //         );
//     //         error!("{}", err_msg);
//     //         make_robot_error_response_future(err_msg.as_str())
//     //     }
//     // }
//     // dispatch_robot_message_with_payload(app, project_name, req_msg, req.take_payload())
// }

// fn dispatch_robot_message_with_payload(
//     app: AppEnvironment,
//     project_name: Arc<String>,
//     req_msg: WXWorkRobotPostMessage,
//     body: web::Payload,
// ) -> HttpResponseFuture {
//     Box::new(
//         body.map_err(Error::from)
//             .fold(web::BytesMut::new(), move |mut body, chunk| {
//                 debug!("test chunk {}", hex::encode(&chunk));
//                 body.extend_from_slice(&chunk);
//                 Ok::<web::BytesMut, Error>(body)
//             })
//             .then(move |fold_bytes_res| match fold_bytes_res {
//                 Ok(x) => dispatch_robot_message(app, project_name, req_msg, x.freeze()),
//                 Err(e) => {
//                     let err_msg = format!(
//                         "project \"{}\" request payload error, {:?}",
//                         project_name, e
//                     );
//                     error!("{}", err_msg);
//                     if let Some(v) = app.get_project(project_name.as_str()) {
//                         Box::new(future_ok(v.make_error_response(err_msg)))
//                     } else {
//                         Box::new(future_ok(message::make_robot_error_response(err_msg)))
//                     }
//                 }
//             }),
//     )
// }

fn dispatch_robot_message(
    app: AppEnvironment,
    project_name: Arc<String>,
    req_msg: WXWorkRobotPostMessage,
    bytes: web::Bytes,
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

    let proj_obj = if let Some(v) = app.get_project(project_name.as_str()) {
        v
    } else {
        return Box::new(future_ok(message::make_robot_error_response_content(
            format!("project \"{}\" not found", project_name).as_str(),
        )));
    };

    debug!(
        "project \"{}\" try to decode {} bytes data: {}",
        project_name,
        bytes.len(),
        match String::from_utf8(bytes.to_vec()) {
            Ok(x) => x,
            Err(_) => hex::encode(&bytes),
        }
    );
    let encrypt_msg_b64 = if let Some(x) = message::get_msg_encrypt_from_bytes(bytes) {
        x
    } else {
        return Box::new(future_ok(message::make_robot_error_response_content(
            format!("project \"{}\" can not decode message body", project_name).as_str(),
        )));
    };

    if !proj_obj.check_msg_signature(
        req_msg.msg_signature.as_str(),
        req_msg.timestamp.as_str(),
        req_msg.nonce.as_str(),
        encrypt_msg_b64.as_str(),
    ) {
        return Box::new(future_ok(message::make_robot_error_response_content(
            format!(
                "project \"{}\" check msg_signature for message {} failed",
                project_name, encrypt_msg_b64
            )
            .as_str(),
        )));
    }

    debug!(
        "project \"{}\" check msg_signature for message {} and passed",
        project_name, encrypt_msg_b64
    );

    let msg_dec = if let Ok(x) = proj_obj.decrypt_msg_raw_base64_content(encrypt_msg_b64.as_str()) {
        x
    } else {
        return Box::new(future_ok(message::make_robot_error_response_content(
            format!(
                "project \"{}\" decrypt message {} failed",
                project_name, encrypt_msg_b64
            )
            .as_str(),
        )));
    };

    // 提取数据
    let msg_ntf = if let Some(x) = message::get_msg_from_str(msg_dec.content.as_str()) {
        x
    } else {
        return Box::new(future_ok(message::make_robot_error_response_content(
            format!(
                "project \"{}\" get message from {} failed",
                project_name, msg_dec.content
            )
            .as_str(),
        )));
    };

    let default_cmd_name = if msg_ntf.content.trim().is_empty() {
        ""
    } else {
        "default"
    };
    // 查找匹配命令
    let (cmd_ptr, mut cmd_match_res, is_default_cmd) =
        if let Some((x, y)) = proj_obj.try_commands(&msg_ntf.content, false) {
            // project 域内查找命令
            (x, y, false)
        } else if let Some((x, y)) = app.get_global_command(&msg_ntf.content, false) {
            // global 域内查找命令
            (x, y, false)
        } else if let Some((x, y)) = proj_obj.try_commands(default_cmd_name, true) {
            // project 域内查找默认命令
            (x, y, true)
        } else if let Some((x, y)) = app.get_global_command(default_cmd_name, true) {
            // global 域内查找默认命令
            (x, y, true)
        } else {
            if default_cmd_name.is_empty() {
                return Box::new(future_ok(message::make_robot_empty_response()));
            } else {
                return Box::new(future_ok(message::make_robot_not_found_response(format!(
                    "project \"{}\" get command from {} failed",
                    project_name, msg_ntf.content
                ))));
            }
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
    cmd_match_res.mut_json()["WXWORK_ROBOT_CHAT_TYPE"] =
        serde_json::Value::String(msg_ntf.chat_type.clone());

    // 填充模板参数json
    let template_vars = proj_obj.generate_template_vars(&cmd_match_res);
    let runtime = Arc::new(command_runtime::WXWorkCommandRuntime {
        proj: proj_obj.clone(),
        cmd: cmd_ptr,
        cmd_match: cmd_match_res,
        envs: template_vars,
        msg: msg_ntf,
    });

    Box::new(
        // 执行命令，返回执行结果Future
        command_runtime::run(runtime).then(move |final_res| match final_res {
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
        }),
    )
}
