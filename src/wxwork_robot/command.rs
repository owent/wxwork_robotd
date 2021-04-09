use std::collections::HashMap;
use std::sync::Arc;

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
pub struct WxWorkCommandHelp {
    pub prefix: String,
    pub suffix: String,
}

#[derive(Debug, Clone)]
pub struct WxWorkCommandEcho {
    pub echo: String,
}

#[derive(Debug, Clone, Copy)]
pub enum WxWorkCommandSpawnOutputType {
    Markdown,
    Text,
    Image,
}

#[derive(Debug, Clone)]
pub struct WxWorkCommandSpawn {
    pub exec: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub output_type: WxWorkCommandSpawnOutputType,
}

#[derive(Debug, Clone, Copy)]
pub enum WxWorkCommandHttpMethod {
    Auto,
    Get,
    Post,
    Delete,
    Head,
    Put,
}

#[derive(Debug, Clone)]
pub struct WxWorkCommandHttp {
    pub url: String,
    pub echo: String,
    pub post: String,
    pub method: WxWorkCommandHttpMethod,
    pub content_type: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum WxWorkCommandData {
    Echo(Arc<WxWorkCommandEcho>),
    Spawn(Arc<WxWorkCommandSpawn>),
    Http(Arc<WxWorkCommandHttp>),
    Help(Arc<WxWorkCommandHelp>),
    Ignore,
}

#[derive(Debug, Clone)]
pub struct WxWorkCommand {
    pub data: WxWorkCommandData,
    name: Arc<String>,
    pub envs: serde_json::Value,
    rule: Regex,
    config: serde_json::Value,
    pub hidden: bool,
    pub description: Arc<String>,
    pub order: i64,
}

#[derive(Debug, Clone)]
pub struct WxWorkCommandMatch(serde_json::Value);

pub type WxWorkCommandPtr = Arc<WxWorkCommand>;
pub type WxWorkCommandList = Vec<WxWorkCommandPtr>;

pub fn read_string_from_json_object(json: &serde_json::Value, name: &str) -> Option<String> {
    if let Some(ref x) = json.as_object() {
        if let Some(ref v) = x.get(name) {
            if let Some(r) = v.as_str() {
                return Some(String::from(r));
            }
        }
    }

    None
}

pub fn read_object_from_json_object<'a>(
    json: &'a serde_json::Value,
    name: &str,
) -> Option<&'a serde_json::map::Map<String, serde_json::Value>> {
    if let Some(ref x) = json.as_object() {
        if let Some(ref v) = x.get(name) {
            if let Some(r) = v.as_object() {
                return Some(r);
            }
        }
    }

    None
}

pub fn read_bool_from_json_object(json: &serde_json::Value, name: &str) -> Option<bool> {
    if let Some(ref x) = json.as_object() {
        if let Some(v) = x.get(name) {
            return match v {
                serde_json::Value::Null => None,
                serde_json::Value::Bool(r) => Some(*r),
                serde_json::Value::Number(r) => {
                    if let Some(rv) = r.as_i64() {
                        Some(rv != 0)
                    } else if let Some(rv) = r.as_u64() {
                        Some(rv != 0)
                    } else if let Some(rv) = r.as_f64() {
                        Some(rv != 0.0)
                    } else {
                        Some(false)
                    }
                }
                serde_json::Value::String(r) => {
                    let lc_name = r.to_lowercase();
                    Some(
                        !lc_name.is_empty()
                            && lc_name.as_str() != "false"
                            && lc_name.as_str() != "no"
                            && lc_name.as_str() != "disable"
                            && lc_name.as_str() != "disabled",
                    )
                }
                serde_json::Value::Array(r) => Some(!r.is_empty()),
                serde_json::Value::Object(r) => Some(!r.is_empty()),
            };
        }
    }

    None
}

pub fn read_array_from_json_object<'a>(
    json: &'a serde_json::Value,
    name: &str,
) -> Option<&'a Vec<serde_json::Value>> {
    if let Some(ref x) = json.as_object() {
        if let Some(ref v) = x.get(name) {
            if let Some(r) = v.as_array() {
                return Some(r);
            }
        }
    }

    None
}

pub fn read_i64_from_json_object(json: &serde_json::Value, name: &str) -> Option<i64> {
    if let Some(ref x) = json.as_object() {
        if let Some(v) = x.get(name) {
            return match v {
                serde_json::Value::Null => None,
                serde_json::Value::Bool(_) => None,
                serde_json::Value::Number(r) => {
                    if let Some(rv) = r.as_i64() {
                        Some(rv)
                    } else if let Some(rv) = r.as_u64() {
                        Some(rv as i64)
                    } else if let Some(rv) = r.as_f64() {
                        Some(rv as i64)
                    } else {
                        Some(0)
                    }
                }
                serde_json::Value::String(r) => {
                    if let Ok(rv) = r.parse::<i64>() {
                        Some(rv)
                    } else {
                        None
                    }
                }
                serde_json::Value::Array(_) => None,
                serde_json::Value::Object(_) => None,
            };
        }
    }

    None
}

pub fn merge_envs(mut l: serde_json::Value, r: &serde_json::Value) -> serde_json::Value {
    if !l.is_object() {
        return l;
    }

    if !r.is_object() {
        return l;
    }

    if let Some(kvs) = r.as_object() {
        for (k, v) in kvs {
            match v {
                serde_json::Value::Null => {
                    l[k] = v.clone();
                }
                serde_json::Value::Bool(_) => {
                    l[k] = v.clone();
                }
                serde_json::Value::Number(_) => {
                    l[k] = v.clone();
                }
                serde_json::Value::String(_) => {
                    l[k] = v.clone();
                }
                _ => {}
            }
        }
    }

    l
}

impl WxWorkCommand {
    pub fn parse(json: &serde_json::Value) -> WxWorkCommandList {
        let mut ret: WxWorkCommandList = Vec::new();

        if let Some(kvs) = json.as_object() {
            for (k, v) in kvs {
                let cmd_res = WxWorkCommand::new(k, v);
                if let Some(cmd) = cmd_res {
                    ret.push(Arc::new(cmd));
                }
            }
        }

        ret.sort_by(|l, r| {
            if l.order != r.order {
                l.order.cmp(&r.order)
            } else {
                l.name().cmp(&r.name())
            }
        });

        ret
    }

    pub fn new(cmd_name: &str, json: &serde_json::Value) -> Option<WxWorkCommand> {
        let cmd_data: WxWorkCommandData;
        let mut envs_obj = json!({});
        // read_bool_from_json_object
        let mut reg_builder = RegexBuilder::new(cmd_name);
        reg_builder.case_insensitive(
            if let Some(v) = read_bool_from_json_object(json, "case_insensitive") {
                v
            } else {
                true
            },
        );
        reg_builder.multi_line(
            if let Some(v) = read_bool_from_json_object(json, "multi_line") {
                v
            } else {
                true
            },
        );
        reg_builder.unicode(
            if let Some(v) = read_bool_from_json_object(json, "unicode") {
                v
            } else {
                true
            },
        );
        reg_builder.octal(if let Some(v) = read_bool_from_json_object(json, "octal") {
            v
        } else {
            false
        });
        reg_builder.octal(
            if let Some(v) = read_bool_from_json_object(json, "dot_matches_new_line") {
                v
            } else {
                false
            },
        );
        let rule_obj = match reg_builder.build() {
            Ok(x) => x,
            Err(e) => {
                error!("command {} regex invalid: {}\n{}", cmd_name, json, e);
                return None;
            }
        };

        {
            if !json.is_object() {
                error!(
                    "command {} configure must be a json object, but real is {}",
                    cmd_name, json
                );
                return None;
            };

            let type_name = if let Some(x) = read_string_from_json_object(json, "type") {
                x
            } else {
                error!("command {} configure require type: {}", cmd_name, json);
                return None;
            };

            cmd_data = match type_name.to_lowercase().as_str() {
                "echo" => WxWorkCommandData::Echo(Arc::new(WxWorkCommandEcho {
                    echo: if let Some(x) = read_string_from_json_object(json, "echo") {
                        x
                    } else {
                        String::from("Ok")
                    },
                })),
                "spawn" => {
                    let exec_field = if let Some(x) = read_string_from_json_object(json, "exec") {
                        x
                    } else {
                        error!("spawn command {} requires exec: {}", cmd_name, json);
                        return None;
                    };

                    let mut args_field: Vec<String> = Vec::new();
                    if let Some(arr) = read_array_from_json_object(json, "args") {
                        for v in arr {
                            args_field.push(match v {
                                serde_json::Value::Null => String::default(),
                                serde_json::Value::Bool(x) => {
                                    if *x {
                                        String::from("true")
                                    } else {
                                        String::from("false")
                                    }
                                }
                                serde_json::Value::Number(x) => x.to_string(),
                                serde_json::Value::String(x) => x.clone(),
                                x => x.to_string(),
                            });
                        }
                    }

                    let cwd_field = if let Some(x) = read_string_from_json_object(json, "cwd") {
                        x
                    } else {
                        String::default()
                    };

                    WxWorkCommandData::Spawn(Arc::new(WxWorkCommandSpawn {
                        exec: exec_field,
                        args: args_field,
                        cwd: cwd_field,
                        output_type: match read_string_from_json_object(json, "output_type") {
                            Some(x) => match x.to_lowercase().as_str() {
                                "text" => WxWorkCommandSpawnOutputType::Text,
                                "image" => WxWorkCommandSpawnOutputType::Image,
                                _ => WxWorkCommandSpawnOutputType::Markdown,
                            },
                            None => WxWorkCommandSpawnOutputType::Markdown,
                        },
                    }))
                }
                "http" => {
                    let url_field = if let Some(x) = read_string_from_json_object(json, "url") {
                        x
                    } else {
                        error!("http command {} requires url: {}", cmd_name, json);
                        return None;
                    };
                    let echo_field = if let Some(x) = read_string_from_json_object(json, "echo") {
                        x
                    } else {
                        String::from("Ok")
                    };
                    let post_field = if let Some(x) = read_string_from_json_object(json, "post") {
                        x
                    } else {
                        String::from("Ok")
                    };

                    WxWorkCommandData::Http(Arc::new(WxWorkCommandHttp {
                        url: url_field,
                        echo: echo_field,
                        post: post_field,
                        method: match read_string_from_json_object(json, "method") {
                            Some(x) => match x.to_lowercase().as_str() {
                                "get" => WxWorkCommandHttpMethod::Get,
                                "post" => WxWorkCommandHttpMethod::Post,
                                "delete" => WxWorkCommandHttpMethod::Delete,
                                "put" => WxWorkCommandHttpMethod::Put,
                                "head" => WxWorkCommandHttpMethod::Head,
                                _ => WxWorkCommandHttpMethod::Auto,
                            },
                            None => WxWorkCommandHttpMethod::Auto,
                        },
                        content_type: if let Some(x) =
                            read_string_from_json_object(json, "content_type")
                        {
                            x
                        } else {
                            String::default()
                        },
                        headers: if let Some(m) = read_object_from_json_object(json, "headers") {
                            let mut res = HashMap::new();
                            for (k, v) in m {
                                res.insert(
                                    k.clone(),
                                    match v {
                                        serde_json::Value::Null => String::default(),
                                        serde_json::Value::Bool(x) => {
                                            if *x {
                                                String::from("true")
                                            } else {
                                                String::from("false")
                                            }
                                        }
                                        serde_json::Value::Number(x) => x.to_string(),
                                        serde_json::Value::String(x) => x.clone(),
                                        x => x.to_string(),
                                    },
                                );
                            }

                            res
                        } else {
                            HashMap::new()
                        },
                    }))
                }
                "help" => WxWorkCommandData::Help(Arc::new(WxWorkCommandHelp {
                    prefix: if let Some(x) = read_string_from_json_object(json, "prefix") {
                        x
                    } else {
                        String::default()
                    },
                    suffix: if let Some(x) = read_string_from_json_object(json, "suffix") {
                        x
                    } else {
                        String::default()
                    },
                })),
                "ignore" => WxWorkCommandData::Ignore,
                _ => {
                    error!("command {} configure type invalid: {}", cmd_name, json);
                    return None;
                }
            };

            if let Some(envs_kvs) = read_object_from_json_object(json, "env") {
                for (k, v) in envs_kvs {
                    envs_obj[format!("WXWORK_ROBOT_CMD_{}", k).as_str().to_uppercase()] =
                        if v.is_string() {
                            v.clone()
                        } else {
                            serde_json::Value::String(v.to_string())
                        };
                }
            }
        }

        Some(WxWorkCommand {
            data: cmd_data,
            name: Arc::new(String::from(cmd_name)),
            rule: rule_obj,
            envs: envs_obj,
            config: json.clone(),
            hidden: if let Some(x) = read_bool_from_json_object(json, "hidden") {
                x
            } else {
                false
            },
            description: if let Some(x) = read_string_from_json_object(json, "description") {
                Arc::new(x)
            } else {
                Arc::new(String::default())
            },
            order: if let Some(x) = read_i64_from_json_object(json, "order") {
                x
            } else {
                0
            },
        })
    }

    pub fn name(&self) -> Arc<String> {
        self.name.clone()
    }

    pub fn try_capture(&self, message: &str) -> WxWorkCommandMatch {
        let caps = if let Some(x) = self.rule.captures(message) {
            x
        } else {
            return WxWorkCommandMatch(serde_json::Value::Null);
        };

        let mut json = self.envs.clone();
        json["WXWORK_ROBOT_CMD"] =
            serde_json::Value::String(String::from(caps.get(0).unwrap().as_str()));

        for cap_name in self.rule.capture_names() {
            if let Some(key) = cap_name {
                if let Some(m) = caps.name(key) {
                    json[format!("WXWORK_ROBOT_CMD_{}", key).as_str().to_uppercase()] =
                        serde_json::Value::String(String::from(m.as_str()));
                }
            }
        }

        WxWorkCommandMatch(json)
    }

    pub fn description(&self) -> Arc<String> {
        self.description.clone()
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden
    }
}

impl WxWorkCommandMatch {
    pub fn has_result(&self) -> bool {
        self.0.is_object()
    }

    pub fn ref_json(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn mut_json(&mut self) -> &mut serde_json::Value {
        &mut self.0
    }
}

pub fn get_command_description(cmd: &WxWorkCommandPtr) -> Option<Arc<String>> {
    if cmd.is_hidden() {
        None
    } else {
        let desc = cmd.description();
        if !desc.is_empty() {
            Some(desc)
        } else {
            Some(cmd.name())
        }
    }
}
