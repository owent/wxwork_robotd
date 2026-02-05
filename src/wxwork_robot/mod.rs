pub mod base64;
pub mod command;
pub mod command_runtime;
pub mod error;
pub mod message;
pub mod project;

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct WxWorkProjectSet {
    pub projs: project::WxWorkProjectMap,
    pub cmds: Arc<command::WxWorkCommandList>,
    pub events: Arc<command::WxWorkCommandList>,
}

pub type WxWorkProjectSetShared = Arc<Mutex<WxWorkProjectSet>>;

lazy_static! {
    pub static ref GLOBAL_EMPTY_JSON_NULL: serde_json::Value = serde_json::Value::Null;
}

pub fn build_project_set(json: &serde_json::Value) -> Option<WxWorkProjectSet> {
    let kvs = if let Some(x) = json.as_object() {
        x
    } else {
        error!(
            "project set configure must be a json object, but real is {}",
            json
        );
        return None;
    };

    let projs_json_conf = if let Some(x) = kvs.get("projects") {
        x
    } else {
        error!("project set configure must has projects field {}", json);
        return None;
    };

    let cmds_json_conf = if let Some(x) = kvs.get("cmds") {
        x
    } else {
        &GLOBAL_EMPTY_JSON_NULL
    };

    let events_json_conf = if let Some(x) = kvs.get("events") {
        x
    } else {
        &GLOBAL_EMPTY_JSON_NULL
    };

    let ret = WxWorkProjectSet {
        projs: project::WxWorkProject::parse(projs_json_conf),
        cmds: Arc::new(command::WxWorkCommand::parse(cmds_json_conf)),
        events: Arc::new(command::WxWorkCommand::parse(events_json_conf)),
    };

    Some(ret)
}

pub fn build_project_set_shared(json: &serde_json::Value) -> Option<WxWorkProjectSetShared> {
    build_project_set(json).map(|x| Arc::new(Mutex::new(x)))
}
