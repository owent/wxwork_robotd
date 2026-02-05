// Copyright (c) 2026 owent

use actix_web::HttpResponse;

use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use regex::{Regex, RegexBuilder};

use tokio::process::Command;
use tokio::time::timeout;

use actix_web::http;
use awc;

use handlebars::Handlebars;

use super::super::app;
use super::{command, message, project};

// #[derive(Clone)]
pub struct WxWorkCommandRuntime {
    pub proj: project::WxWorkProjectPtr,
    pub cmd: command::WxWorkCommandPtr,
    pub cmd_match: command::WxWorkCommandMatch,
    pub envs: serde_json::Value,
    pub msg: message::WxWorkMessageNtf,
}

lazy_static! {
    static ref PICK_AT_RULE: Regex = RegexBuilder::new(r"@(?P<AT>\S+)")
        .case_insensitive(false)
        .build()
        .unwrap();
}

pub fn get_project_name_from_runtime(runtime: &Arc<WxWorkCommandRuntime>) -> Arc<String> {
    runtime.proj.name()
}

pub fn get_command_name_from_runtime(runtime: &Arc<WxWorkCommandRuntime>) -> Arc<String> {
    runtime.cmd.name()
}

// #[allow(unused)]
pub async fn run(runtime: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    debug!(
        "dispatch for command \"{}\"({})",
        runtime.cmd.name(),
        runtime.cmd.description()
    );

    match runtime.cmd.data {
        command::WxWorkCommandData::Echo(_) => run_echo(runtime).await,
        command::WxWorkCommandData::Http(_) => run_http(runtime).await,
        command::WxWorkCommandData::Help(_) => run_help(runtime).await,
        command::WxWorkCommandData::Spawn(_) => run_spawn(runtime).await,
        command::WxWorkCommandData::Ignore => run_ignore(runtime).await,
        // _ => run_test,
    }
}

#[allow(unused)]
async fn run_test(_: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("test success")
}

async fn run_ignore(_: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    message::make_robot_empty_response()
}

async fn run_help(runtime: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    let (echo_prefix, echo_suffix) =
        if let command::WxWorkCommandData::Help(ref x) = runtime.cmd.data {
            (x.prefix.clone(), x.suffix.clone())
        } else {
            (String::default(), String::default())
        };

    let mut output = String::with_capacity(4096);
    let reg = Handlebars::new();
    if !echo_prefix.is_empty() {
        output += (match reg.render_template(echo_prefix.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        })
        .as_str();
        output += "\r\n";
    }

    let mut cmd_index = 1;
    for cmd in runtime.proj.cmds.as_ref() {
        if let Some(desc) = command::get_command_description(cmd) {
            output += format!("> {}. {}\r\n", cmd_index, desc).as_str();
            cmd_index += 1;
        }
    }

    let app_env = app::app();
    for cmd in app_env.get_global_command_list().as_ref() {
        if let Some(desc) = command::get_command_description(cmd) {
            output += format!("> {}. {}\r\n", cmd_index, desc).as_str();
            cmd_index += 1;
        }
    }

    if !echo_suffix.is_empty() {
        output += (match reg.render_template(echo_suffix.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        })
        .as_str();
    }

    debug!("Help message: \n{}", output);

    runtime.proj.make_markdown_response_with_text(output)
}

async fn run_echo(runtime: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    let echo_input = if let command::WxWorkCommandData::Echo(ref x) = runtime.cmd.data {
        x.echo.clone()
    } else {
        String::from("Hello world!")
    };

    let reg = Handlebars::new();
    let echo_output = match reg.render_template(echo_input.as_str(), &runtime.envs) {
        Ok(x) => x,
        Err(e) => format!("{:?}", e),
    };

    debug!("Echo message: \n{}", echo_output);
    runtime.proj.make_markdown_response_with_text(echo_output)
}

async fn run_http(runtime: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    let http_req_f;
    let http_url;
    let reg;
    let echo_output_tmpl_str;

    {
        let http_data = if let command::WxWorkCommandData::Http(ref x) = runtime.cmd.data {
            x.clone()
        } else {
            return runtime
                .proj
                .make_error_response(String::from("Configure type error"));
        };

        if http_data.url.is_empty() {
            let err_msg = "Missing Request URL".to_string();
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return runtime.proj.make_error_response(err_msg);
        }

        reg = Handlebars::new();
        http_url = match reg.render_template(http_data.url.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        };

        echo_output_tmpl_str = if http_data.echo.is_empty() {
            String::from("Ok")
        } else {
            http_data.echo.clone()
        };
        let post_data = reg
            .render_template(http_data.post.as_str(), &runtime.envs)
            .unwrap_or_default();

        {
            let mut http_request = match http_data.method {
                command::WxWorkCommandHttpMethod::Auto => {
                    if !post_data.is_empty() {
                        awc::Client::default().post(http_url.as_str())
                    } else {
                        awc::Client::default().get(http_url.as_str())
                    }
                }
                command::WxWorkCommandHttpMethod::Get => {
                    awc::Client::default().get(http_url.as_str())
                }
                command::WxWorkCommandHttpMethod::Post => {
                    awc::Client::default().post(http_url.as_str())
                }
                command::WxWorkCommandHttpMethod::Delete => {
                    awc::Client::default().delete(http_url.as_str())
                }
                command::WxWorkCommandHttpMethod::Put => {
                    awc::Client::default().put(http_url.as_str())
                }
                command::WxWorkCommandHttpMethod::Head => {
                    awc::Client::default().head(http_url.as_str())
                }
            };
            http_request = http_request
                .timeout(Duration::from_millis(app::app_conf().task_timeout))
                .insert_header_if_none((
                    http::header::USER_AGENT,
                    format!("Mozilla/5.0 (WXWork-Robotd {})", crate_version!()),
                ));
            if !http_data.content_type.is_empty() {
                http_request = http_request.insert_header_if_none((
                    http::header::CONTENT_TYPE,
                    http_data.content_type.as_str(),
                ));
            }
            for (k, v) in &http_data.headers {
                http_request = http_request.insert_header_if_none((k.as_str(), v.as_str()));
            }

            http_req_f = http_request.send_body(post_data);
        }

        // if let Err(e) = http_req_f {
        //     let err_msg = format!("Make request to {} failed, {:?}", http_url, e);
        //     error!(
        //         "project \"{}\" command \"{}\" {}",
        //         runtime.proj.name(),
        //         runtime.cmd.name(),
        //         err_msg
        //     );
        //     return Box::new(future_ok(runtime.proj.make_error_response(err_msg)));
        // }
    }

    let mut http_rsp = match http_req_f.await {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("Make request to {} failed, {:?}", http_url, e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return runtime.proj.make_error_response(err_msg);
        }
    };

    let rsp_data = match http_rsp.body().await {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("{:?}", e);
            error!(
                "project \"{}\" command \"{}\" get response from {} failed: {:?}",
                get_project_name_from_runtime(&runtime),
                get_command_name_from_runtime(&runtime),
                http_url,
                err_msg
            );
            return runtime.proj.make_markdown_response_with_text(err_msg);
        }
    };

    let data_str = if let Ok(x) = String::from_utf8(rsp_data.to_vec()) {
        x
    } else {
        hex::encode(&rsp_data)
    };

    info!(
        "project \"{}\" command \"{}\" get response from {}: \n{:?}",
        get_project_name_from_runtime(&runtime),
        get_command_name_from_runtime(&runtime),
        http_url,
        data_str
    );

    let mut vars_for_rsp = runtime.envs.clone();
    if vars_for_rsp.is_object() {
        vars_for_rsp["WXWORK_ROBOT_HTTP_RESPONSE"] = serde_json::Value::String(data_str);
    }
    let echo_output = match reg.render_template(echo_output_tmpl_str.as_str(), &vars_for_rsp) {
        Ok(x) => x,
        Err(e) => format!("{:?}", e),
    };
    runtime.proj.make_markdown_response_with_text(echo_output)
}

async fn run_spawn(runtime: Arc<WxWorkCommandRuntime>) -> HttpResponse {
    let spawn_data = if let command::WxWorkCommandData::Spawn(ref x) = runtime.cmd.data {
        x.clone()
    } else {
        return runtime
            .proj
            .make_error_response(String::from("Configure type error"));
    };

    let reg = Handlebars::new();
    let exec = match reg.render_template(spawn_data.exec.as_str(), &runtime.envs) {
        Ok(x) => x,
        Err(_) => spawn_data.exec.clone(),
    };
    let cwd = match reg.render_template(spawn_data.cwd.as_str(), &runtime.envs) {
        Ok(x) => x,
        Err(_) => spawn_data.cwd.clone(),
    };

    let mut args = Vec::with_capacity(spawn_data.args.capacity());
    for v in &spawn_data.args {
        args.push(match reg.render_template(v.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(_) => v.clone(),
        });
    }

    let output_type = spawn_data.output_type;

    info!("Spawn message: (CWD={}) {} {}", cwd, exec, &args.join(" "));
    let mut child = Command::new(exec.as_str());
    child.stdin(Stdio::null());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());
    child.kill_on_drop(true);

    for ref v in args {
        child.arg(v.as_str());
    }

    if let Some(kvs) = runtime.envs.as_object() {
        for (k, v) in kvs {
            match v {
                serde_json::Value::Null => {}
                serde_json::Value::Bool(x) => {
                    child.env(k.as_str(), if *x { "1" } else { "0" });
                }
                serde_json::Value::Number(x) => {
                    child.env(k.as_str(), x.to_string());
                }
                serde_json::Value::String(x) => {
                    child.env(k.as_str(), x.as_str());
                }
                x => {
                    child.env(k.as_str(), x.to_string());
                }
            }
        }
    }

    if !cwd.is_empty() {
        child.current_dir(cwd);
    }

    let async_job = match child.spawn() {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("Run command failed, {:?}", e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return runtime.proj.make_error_response(err_msg);
        }
    };

    let run_result = match timeout(
        Duration::from_millis(app::app_conf().task_timeout),
        async_job.wait_with_output(),
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("Run command timeout, {:?}", e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return runtime.proj.make_markdown_response_with_text(err_msg);
        }
    };

    let output = match run_result {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("Run command with io error, {:?}", e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return runtime.proj.make_markdown_response_with_text(err_msg);
        }
    };

    let mut ret_msg = String::with_capacity(output.stdout.len() + output.stderr.len() + 32);
    if !output.stdout.is_empty() {
        ret_msg += (match String::from_utf8(output.stdout) {
            Ok(x) => x,
            Err(e) => hex::encode(e.as_bytes()),
        })
        .as_str();
    }

    if !output.stderr.is_empty() {
        let stderr_str = match String::from_utf8(output.stderr) {
            Ok(x) => x,
            Err(e) => hex::encode(e.as_bytes()),
        };

        info!(
            "project \"{}\" command \"{}\" run command with stderr:\n{}",
            runtime.proj.name(),
            runtime.cmd.name(),
            stderr_str
        );
        ret_msg += stderr_str.as_str();
    }

    if output.status.success() {
        match output_type {
            command::WxWorkCommandSpawnOutputType::Markdown => {
                runtime.proj.make_markdown_response_with_text(ret_msg)
            }
            command::WxWorkCommandSpawnOutputType::Text => {
                let mut mentioned_list: Vec<String> = Vec::new();

                for caps in PICK_AT_RULE.captures_iter(ret_msg.as_str()) {
                    if let Some(m) = caps.name("AT") {
                        mentioned_list.push(String::from(m.as_str()));
                    }
                }

                let rsp = message::WxWorkMessageTextRsp {
                    content: ret_msg,
                    mentioned_list,
                    mentioned_mobile_list: Vec::new(),
                };

                runtime.proj.make_text_response(rsp)
            }
            command::WxWorkCommandSpawnOutputType::Image => {
                let file_path = ret_msg.trim();
                let mut options = OpenOptions::new();
                options
                    .write(false)
                    .create(false)
                    .truncate(false)
                    .read(true);
                let mut err_msg = String::default();
                let mut image_data: Vec<u8> = Vec::new();

                if !file_path.is_empty() {
                    match options.open(file_path) {
                        Ok(f) => {
                            let mut reader = BufReader::new(f);
                            match reader.read_to_end(&mut image_data) {
                                Ok(_) => {}
                                Err(e) => {
                                    err_msg =
                                        format!("Try read data from {} failed, {:?}", file_path, e);
                                }
                            }
                        }
                        Err(e) => {
                            err_msg = format!("Try to open {} failed, {:?}", file_path, e);
                        }
                    };
                }

                if !image_data.is_empty() {
                    runtime
                        .proj
                        .make_image_response(message::WxWorkMessageImageRsp {
                            content: image_data,
                        })
                } else {
                    runtime
                        .proj
                        .make_text_response(message::WxWorkMessageTextRsp {
                            content: err_msg,
                            mentioned_list: vec![runtime.msg.from.alias.clone()],
                            mentioned_mobile_list: Vec::new(),
                        })
                }
            }
        }
    } else {
        runtime
            .proj
            .make_text_response(message::WxWorkMessageTextRsp {
                content: ret_msg,
                mentioned_list: vec![runtime.msg.from.alias.clone()],
                mentioned_mobile_list: Vec::new(),
            })
    }
    //Box::new(future_ok(runtime.proj.make_markdown_response_with_text(echo_output)))
}
