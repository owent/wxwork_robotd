use actix_web::{AsyncResponder, HttpResponse};
use futures::future::{ok as future_ok, Either, Future};
use futures::Stream;

use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use tokio::util::FutureExt;
use tokio_process::CommandExt;

use actix_web::{client, http, HttpMessage};

use handlebars::Handlebars;
use serde_json;

use super::super::app;
use super::{command, error, message, project};

pub type HttpResponseFuture = Box<Future<Item = HttpResponse, Error = error::Error>>;

#[derive(Clone)]
pub struct WXWorkCommandRuntime {
    pub proj: project::WXWorkProjectPtr,
    pub cmd: command::WXWorkCommandPtr,
    pub cmd_match: command::WXWorkCommandMatch,
    pub envs: serde_json::Value,
    pub msg: message::WXWorkMessageNtf,
}

lazy_static! {
    static ref PICK_AT_RULE: Regex = RegexBuilder::new("\\@(?P<AT>[\\B]+)")
        .case_insensitive(false)
        .build()
        .unwrap();
}

pub fn get_project_name_from_runtime(runtime: &Arc<WXWorkCommandRuntime>) -> Arc<String> {
    runtime.proj.name()
}

pub fn get_command_name_from_runtime(runtime: &Arc<WXWorkCommandRuntime>) -> Arc<String> {
    runtime.cmd.name()
}

// #[allow(unused)]
pub fn run(
    runtime: Arc<WXWorkCommandRuntime>,
) -> impl Future<Item = HttpResponse, Error = error::Error> {
    // let borrow_runtime = &runtime;
    let call_fn: fn(Arc<WXWorkCommandRuntime>) -> HttpResponseFuture;
    {
        debug!(
            "dispatch for command \"{}\"({})",
            runtime.cmd.name(),
            runtime.cmd.description()
        );

        call_fn = match runtime.cmd.data {
            command::WXWorkCommandData::ECHO(_) => run_echo,
            command::WXWorkCommandData::HTTP(_) => run_http,
            command::WXWorkCommandData::HELP(_) => run_help,
            command::WXWorkCommandData::SPAWN(_) => run_spawn,
            // _ => run_test,
        }
    }

    call_fn(runtime)
}

#[allow(unused)]
fn run_test(_: Arc<WXWorkCommandRuntime>) -> HttpResponseFuture {
    future_ok(
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body("test success"),
    ).responder()
}

fn run_help(runtime: Arc<WXWorkCommandRuntime>) -> HttpResponseFuture {
    let (echo_prefix, echo_suffix) =
        if let command::WXWorkCommandData::HELP(ref x) = runtime.cmd.data {
            (x.prefix.clone(), x.suffix.clone())
        } else {
            (String::default(), String::default())
        };

    let mut output = String::with_capacity(4096);
    let reg = Handlebars::new();
    if echo_prefix.len() > 0 {
        output += (match reg.render_template(echo_prefix.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        }).as_str();
        output += "\r\n";
    }

    let mut cmd_index = 1;
    for ref cmd in runtime.proj.cmds.as_ref() {
        if let Some(desc) = command::get_command_description(&cmd) {
            output += format!("> {}. {}\r\n", cmd_index, desc).as_str();
            cmd_index += 1;
        }
    }

    let app_env = app::app();
    for ref cmd in app_env.get_global_command_list().as_ref() {
        if let Some(desc) = command::get_command_description(&cmd) {
            output += format!("> {}. {}\r\n", cmd_index, desc).as_str();
            cmd_index += 1;
        }
    }

    if echo_suffix.len() > 0 {
        output += (match reg.render_template(echo_suffix.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        }).as_str();
    }

    debug!("Help message: \n{}", output);
    future_ok(runtime.proj.make_markdown_response_with_text(output)).responder()
}

fn run_echo(runtime: Arc<WXWorkCommandRuntime>) -> HttpResponseFuture {
    let echo_input = if let command::WXWorkCommandData::ECHO(ref x) = runtime.cmd.data {
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
    future_ok(runtime.proj.make_markdown_response_with_text(echo_output)).responder()
}

fn run_http(runtime: Arc<WXWorkCommandRuntime>) -> HttpResponseFuture {
    let http_req_f;
    let http_url;
    let reg;
    let echo_output_tmpl_str;

    {
        let http_data = if let command::WXWorkCommandData::HTTP(ref x) = runtime.cmd.data {
            x.clone()
        } else {
            return future_ok(
                runtime
                    .proj
                    .make_error_response(String::from("Configure type error")),
            ).responder();
        };

        if 0 == http_data.url.len() {
            let err_msg = format!("Missing Request URL");
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return future_ok(runtime.proj.make_error_response(err_msg)).responder();
        }

        reg = Handlebars::new();
        http_url = match reg.render_template(http_data.url.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(e) => format!("{:?}", e),
        };

        echo_output_tmpl_str = if 0 == http_data.echo.len() {
            String::from("Ok")
        } else {
            http_data.echo.clone()
        };
        let post_data = match reg.render_template(http_data.post.as_str(), &runtime.envs) {
            Ok(x) => x,
            Err(_) => String::default(),
        };

        {
            let mut http_request = match http_data.method {
                command::WXWorkCommandHttpMethod::Auto => {
                    if post_data.len() > 0 {
                        client::post(http_url.as_str())
                    } else {
                        client::get(http_url.as_str())
                    }
                }
                command::WXWorkCommandHttpMethod::Get => client::get(http_url.as_str()),
                command::WXWorkCommandHttpMethod::Post => client::post(http_url.as_str()),
                command::WXWorkCommandHttpMethod::Delete => client::delete(http_url.as_str()),
                command::WXWorkCommandHttpMethod::Put => client::put(http_url.as_str()),
                command::WXWorkCommandHttpMethod::Head => client::head(http_url.as_str()),
            };
            http_request.timeout(Duration::from_millis(app::app_conf().task_timeout));
            http_request.header(
                http::header::USER_AGENT,
                format!("WXWork-Robotd {}", crate_version!()),
            );
            if http_data.content_type.len() > 0 {
                http_request.header(http::header::CONTENT_TYPE, http_data.content_type.as_str());
            }
            for (k, v) in &http_data.headers {
                http_request.header(k.as_str(), v.as_str());
            }

            http_req_f = if post_data.len() > 0 {
                http_request.body(post_data)
            } else {
                http_request.finish()
            };
        }

        if let Err(e) = http_req_f {
            let err_msg = format!("Make request to {} failed, {:?}", http_url, e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return future_ok(runtime.proj.make_error_response(err_msg)).responder();
        }
    }

    let http_req = http_req_f.unwrap();
    http_req
        .send()
        .then(move |response| match response {
            Ok(http_rsp) => Either::A(http_rsp.payload().into_future().then(move |rsp_body| {
                let final_output = match rsp_body {
                    Ok(rsp_pair) => {
                        let data_str = if let Some(data) = rsp_pair.0 {
                            if let Ok(x) = String::from_utf8((&data).to_vec()) {
                                x
                            } else {
                                hex::encode(&data)
                            }
                        } else {
                            String::default()
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
                            vars_for_rsp["WXWORK_ROBOT_HTTP_RESPONSE"] =
                                serde_json::Value::String(data_str);
                        }
                        let echo_output = match reg
                            .render_template(echo_output_tmpl_str.as_str(), &vars_for_rsp)
                        {
                            Ok(x) => x,
                            Err(e) => format!("{:?}", e),
                        };
                        echo_output
                    }
                    Err(e) => {
                        let err_msg = format!("{:?}", e.0);
                        error!(
                            "project \"{}\" command \"{}\" get response from {} failed: {:?}",
                            get_project_name_from_runtime(&runtime),
                            get_command_name_from_runtime(&runtime),
                            http_url,
                            err_msg
                        );
                        err_msg
                    }
                };

                future_ok(runtime.proj.make_markdown_response_with_text(final_output))
            })),
            Err(e) => {
                let err_msg = format!("Make request to {} failed, {:?}", http_url, e);
                error!(
                    "project \"{}\" command \"{}\" {}",
                    runtime.proj.name(),
                    runtime.cmd.name(),
                    err_msg
                );

                Either::B(future_ok(runtime.proj.make_error_response(err_msg)))
            }
        }).responder()
}

fn run_spawn(runtime: Arc<WXWorkCommandRuntime>) -> HttpResponseFuture {
    let spawn_data = if let command::WXWorkCommandData::SPAWN(ref x) = runtime.cmd.data {
        x.clone()
    } else {
        return future_ok(
            runtime
                .proj
                .make_error_response(String::from("Configure type error")),
        ).responder();
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
    child.stdin(Stdio::piped());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());

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

    if cwd.len() > 0 {
        child.current_dir(cwd);
    }

    let async_job = match child.spawn_async() {
        Ok(x) => x,
        Err(e) => {
            let err_msg = format!("Run command failed, {:?}", e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime.proj.name(),
                runtime.cmd.name(),
                err_msg
            );
            return future_ok(runtime.proj.make_error_response(err_msg)).responder();
        }
    };

    let runtime_for_err = runtime.clone();
    let runtime_for_deadline = runtime.clone();
    async_job
        .wait_with_output()
        .map_err(move |e| {
            let err_msg = format!("Run command failed, {:?}", e);
            error!(
                "project \"{}\" command \"{}\" {}",
                runtime_for_err.proj.name(),
                runtime_for_err.cmd.name(),
                err_msg
            );
            error::Error::StringErr(err_msg)
        }).and_then(move |output| {
            let mut ret_msg = String::with_capacity(output.stdout.len() + output.stderr.len() + 32);
            if output.stdout.len() > 0 {
                ret_msg += (match String::from_utf8(output.stdout) {
                    Ok(x) => x,
                    Err(e) => hex::encode(e.as_bytes()),
                }).as_str();
            }

            if output.stderr.len() > 0 {
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
                    command::WXWorkCommandSpawnOutputType::Markdown => {
                        future_ok(runtime.proj.make_markdown_response_with_text(ret_msg))
                    }
                    command::WXWorkCommandSpawnOutputType::Text => {
                        let mut mentioned_list: Vec<String> = Vec::new();

                        for caps in PICK_AT_RULE.captures_iter(ret_msg.as_str()) {
                            if let Some(m) = caps.name("AT") {
                                mentioned_list.push(String::from(m.as_str()));
                            }
                        }

                        let rsp = message::WXWorkMessageTextRsp {
                            content: ret_msg,
                            mentioned_list: mentioned_list,
                            mentioned_mobile_list: Vec::new(),
                        };

                        future_ok(runtime.proj.make_text_response(rsp))
                    }
                    command::WXWorkCommandSpawnOutputType::Image => {
                        let file_path = ret_msg.trim();
                        let mut options = OpenOptions::new();
                        options
                            .write(false)
                            .create(false)
                            .truncate(false)
                            .read(true);
                        let mut err_msg = String::default();
                        let mut image_data: Vec<u8> = Vec::new();

                        if file_path.len() > 0 {
                            match options.open(file_path) {
                                Ok(f) => {
                                    let mut reader = BufReader::new(f);
                                    match reader.read_to_end(&mut image_data) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            err_msg = format!(
                                                "Try read data from {} failed, {:?}",
                                                file_path, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    err_msg = format!("Try to open {} failed, {:?}", file_path, e);
                                }
                            };
                        }

                        if image_data.len() > 0 {
                            future_ok(runtime.proj.make_image_response(
                                message::WXWorkMessageImageRsp {
                                    content: image_data,
                                },
                            ))
                        } else {
                            future_ok(runtime.proj.make_text_response(
                                message::WXWorkMessageTextRsp {
                                    content: err_msg,
                                    mentioned_list: vec![runtime.msg.from.alias.clone()],
                                    mentioned_mobile_list: Vec::new(),
                                },
                            ))
                        }
                    }
                }
            } else {
                future_ok(
                    runtime
                        .proj
                        .make_text_response(message::WXWorkMessageTextRsp {
                            content: ret_msg,
                            mentioned_list: vec![runtime.msg.from.alias.clone()],
                            mentioned_mobile_list: Vec::new(),
                        }),
                )
            }
        }).deadline(Instant::now() + Duration::from_millis(app::app_conf().task_timeout))
        .then(move |timeout_res| match timeout_res {
            Ok(x) => future_ok(x),
            Err(e) => {
                let err_msg = format!("Run command timeout, {:?}", e);
                error!(
                    "project \"{}\" command \"{}\" {}",
                    runtime_for_deadline.proj.name(),
                    runtime_for_deadline.cmd.name(),
                    err_msg
                );
                future_ok(runtime_for_deadline.proj.make_text_response(
                    message::WXWorkMessageTextRsp {
                        content: err_msg,
                        mentioned_list: vec![runtime_for_deadline.msg.from.alias.clone()],
                        mentioned_mobile_list: Vec::new(),
                    },
                ))
            }
        }).responder()
    //future_ok(runtime.proj.make_markdown_response_with_text(echo_output)).responder()
}
