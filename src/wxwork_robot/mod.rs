pub mod base64;
pub mod command;
pub mod command_runtime;
pub mod error;
pub mod message;
pub mod project;

use serde_json;

use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct WXWorkProjectSet {
    pub projs: project::WXWorkProjectMap,
    pub cmds: Rc<command::WXWorkCommandList>,
    pub events: Rc<command::WXWorkCommandList>,
}

pub type WXWorkProjectSetShared = Arc<Mutex<WXWorkProjectSet>>;

lazy_static! {
    pub static ref GLOBAL_EMPTY_JSON_NULL: serde_json::Value = serde_json::Value::Null;
}

pub fn build_project_set(json: &serde_json::Value) -> Option<WXWorkProjectSet> {
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

    let ret = WXWorkProjectSet {
        projs: project::WXWorkProject::parse(projs_json_conf),
        cmds: Rc::new(command::WXWorkCommand::parse(cmds_json_conf)),
        events: Rc::new(command::WXWorkCommand::parse(events_json_conf)),
    };

    Some(ret)
}

pub fn build_project_set_shared(json: &serde_json::Value) -> Option<WXWorkProjectSetShared> {
    if let Some(x) = build_project_set(json) {
        Some(Arc::new(Mutex::new(x)))
    } else {
        None
    }
}
