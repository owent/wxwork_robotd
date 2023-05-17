use quick_xml::events::BytesCData;

use crate::actix_web::web;
use crate::md5::{Digest, Md5};

// use hex;
use crate::quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use crate::quick_xml::name::QName;
use crate::quick_xml::Reader;
use crate::quick_xml::Writer;

use crate::actix_web::HttpResponse;

use crate::regex::{Regex, RegexBuilder};

use std::io::Cursor;

use super::base64;

#[derive(Debug, Clone)]
pub struct WxWorkMessageDec {
    pub content: String,
    pub receiveid: String,
}

#[derive(Debug, Clone)]
pub struct WxWorkMessageFrom {
    pub user_id: String,
    pub name: String,
    pub alias: String,
}

#[derive(Debug, Clone)]
pub struct WxWorkMessageNtf {
    pub web_hook_key: String,
    pub web_hook_url: String,
    pub from: WxWorkMessageFrom,
    pub msg_type: String,
    pub content: String,
    pub image_url: String,
    pub msg_id: String,
    pub post_id: String,
    pub chat_id: String,
    pub chat_type: String,
    pub get_chat_info_url: String,
    pub app_version: String,
    pub event_type: String,
    pub action_name: String,
    pub action_value: String,
    pub action_callbackid: String,
}

#[derive(Debug, Clone)]
pub struct WxWorkMessageTextRsp {
    pub content: String,
    pub mentioned_list: Vec<String>,
    pub mentioned_mobile_list: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct WxWorkMessageMarkdownRsp {
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct WxWorkMessageImageRsp {
    pub content: Vec<u8>,
}

lazy_static! {
    static ref PICK_WEBHOOK_KEY_RULE: Regex = RegexBuilder::new("key=(?P<KEY>[\\d\\w\\-_]+)")
        .case_insensitive(false)
        .build()
        .unwrap();
}

pub fn get_msg_encrypt_from_bytes(bytes: web::Bytes) -> Option<String> {
    let mut reader = Reader::from_reader(bytes.as_ref());
    reader.trim_text(true);
    let mut is_msg_field = false;
    let mut ret = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                if let QName(b"Encrypt") = e.name() {
                    is_msg_field = true;
                }
            }
            Ok(Event::End(ref e)) => {
                if let QName(b"Encrypt") = e.name() {
                    is_msg_field = false;
                }
            }
            Ok(Event::CData(data)) => {
                if is_msg_field {
                    match String::from_utf8(Vec::from(data.into_inner())) {
                        Ok(s) => {
                            ret = Some(s);
                        }
                        Err(e) => {
                            error!("decode Encrypt as utf8 failed, {:?}", e);
                        }
                    }
                }
            }
            Err(e) => error!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => (),
        }
    }

    ret
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WxWorkMsgField {
    None,
    WebHookUrl,
    FromUserId,
    FromName,
    FromAlias,
    MsgType,
    Content,
    MsgId,
    GetChatInfoUrl,
    PostId,
    ChatId,
    ChatType,
    AppVersion,
    EventType,
    ActionName,
    ActionValue,
    ActionCallbackId,
    ImageUrl,
}

pub fn get_msg_from_str(input: &str) -> Option<WxWorkMessageNtf> {
    let mut web_hook_url = String::default();
    let mut from_user_id = String::default();
    let mut from_name = String::default();
    let mut from_alias = String::default();
    let mut msg_type = String::default();
    let mut content = String::default();
    let mut image_url = String::default();
    let mut msg_id = String::default();
    let mut post_id = String::default();
    let mut chat_id = String::default();
    let mut chat_type = String::default();
    let mut get_chat_info_url = String::default();
    let mut app_version = String::default();
    let mut event_type = String::default();
    let mut action_name = String::default();
    let mut action_value = String::default();
    let mut action_callbackid = String::default();
    let mut is_in_from = false;
    let mut is_in_event = false;
    let mut is_in_attachment = false;
    let mut field_mode = WxWorkMsgField::None;

    let mut reader = Reader::from_str(input);
    reader.trim_text(true);

    let mut setter_fn = |data_str, field_mode| match field_mode {
        WxWorkMsgField::WebHookUrl => {
            web_hook_url = data_str;
            debug!("Parse data for WebhookUrl");
        }
        WxWorkMsgField::FromUserId => {
            from_user_id = data_str;
            debug!("Parse data for From.UserId");
        }
        WxWorkMsgField::FromName => {
            from_name = data_str;
            debug!("Parse data for From.Name");
        }
        WxWorkMsgField::FromAlias => {
            from_alias = data_str;
            debug!("Parse data for From.Alias");
        }
        WxWorkMsgField::MsgType => {
            msg_type = data_str;
            debug!("Parse data for MsgType");
        }
        WxWorkMsgField::Content => {
            content = data_str;
            debug!("Parse data for Content");
        }
        WxWorkMsgField::ImageUrl => {
            image_url = data_str;
            debug!("Parse data for ImageUrl");
        }
        WxWorkMsgField::MsgId => {
            msg_id = data_str;
            debug!("Parse data for MsgId");
        }
        WxWorkMsgField::GetChatInfoUrl => {
            get_chat_info_url = data_str;
            debug!("Parse data for GetChatInfoUrl");
        }
        WxWorkMsgField::PostId => {
            post_id = data_str;
            debug!("Parse data for PostId");
        }
        WxWorkMsgField::ChatId => {
            chat_id = data_str;
            debug!("Parse data for ChatId");
        }
        WxWorkMsgField::ChatType => {
            chat_type = data_str;
            debug!("Parse data for ChatType");
        }
        WxWorkMsgField::AppVersion => {
            app_version = data_str;
            debug!("Parse data for AppVersion");
        }
        WxWorkMsgField::EventType => {
            event_type = data_str;
            debug!("Parse data for EventType");
        }
        WxWorkMsgField::ActionCallbackId => {
            action_callbackid = data_str;
            debug!("Parse data for ActionCallbackId");
        }
        WxWorkMsgField::ActionName => {
            action_name = data_str;
            debug!("Parse data for ActionName");
        }
        WxWorkMsgField::ActionValue => {
            action_value = data_str;
            debug!("Parse data for ActionValue");
        }
        _ => {
            debug!("Ignore data {}", data_str);
        }
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let tag_name = e.name();
                match tag_name.into_inner() {
                    b"WebhookUrl" => {
                        field_mode = WxWorkMsgField::WebHookUrl;
                        debug!("Parse get ready for WebhookUrl");
                    }
                    b"From" => {
                        is_in_from = true;
                        debug!("Parse get ready for From");
                    }
                    b"Event" => {
                        is_in_event = true;
                        debug!("Parse get ready for Event");
                    }
                    b"Attachment" => {
                        is_in_attachment = true;
                        debug!("Parse get ready for Attachment");
                    }
                    b"AppVersion" => {
                        field_mode = WxWorkMsgField::AppVersion;
                        debug!("Parse get ready for AppVersion");
                    }
                    b"UserId" => {
                        if is_in_from {
                            field_mode = WxWorkMsgField::FromUserId;
                            debug!("Parse get ready for From.UserId");
                        }
                    }
                    b"Name" => {
                        if is_in_from {
                            field_mode = WxWorkMsgField::FromName;
                            debug!("Parse get ready for From.Name");
                        } else if is_in_attachment {
                            field_mode = WxWorkMsgField::ActionName;
                            debug!("Parse get ready for Attachment.Actions.Name");
                        }
                    }
                    b"Value" => {
                        if is_in_attachment {
                            field_mode = WxWorkMsgField::ActionValue;
                            debug!("Parse get ready for Attachment.Actions.Value");
                        }
                    }
                    b"CallbackId" => {
                        if is_in_attachment {
                            field_mode = WxWorkMsgField::ActionCallbackId;
                            debug!("Parse get ready for Attachment.CallbackId");
                        }
                    }
                    b"Alias" => {
                        if is_in_from {
                            field_mode = WxWorkMsgField::FromAlias;
                            debug!("Parse get ready for From.Alias");
                        }
                    }
                    b"EventType" => {
                        if is_in_event {
                            field_mode = WxWorkMsgField::EventType;
                            debug!("Parse get ready for Event.EventType");
                        }
                    }
                    b"MsgType" => {
                        field_mode = WxWorkMsgField::MsgType;
                        debug!("Parse get ready for MsgType");
                    }
                    b"Text" | b"Markdown" => {
                        field_mode = WxWorkMsgField::Content;
                        debug!("Parse get ready for Content");
                    }
                    b"ImageUrl" => {
                        field_mode = WxWorkMsgField::ImageUrl;
                        debug!("Parse get ready for ImageUrl");
                    }
                    b"MsgId" => {
                        field_mode = WxWorkMsgField::MsgId;
                        debug!("Parse get ready for MsgId");
                    }
                    b"GetChatInfoUrl" => {
                        field_mode = WxWorkMsgField::GetChatInfoUrl;
                        debug!("Parse get ready for GetChatInfoUrl");
                    }
                    b"PostId" => {
                        field_mode = WxWorkMsgField::PostId;
                        debug!("Parse get ready for PostId");
                    }
                    b"ChatId" => {
                        field_mode = WxWorkMsgField::ChatId;
                        debug!("Parse get ready for ChatId");
                    }
                    b"ChatType" => {
                        field_mode = WxWorkMsgField::ChatType;
                        debug!("Parse get ready for ChatType");
                    }
                    any => {
                        debug!(
                            "Ignore start label for {}",
                            if let Ok(x) = String::from_utf8(any.to_vec()) {
                                x
                            } else {
                                String::from("UNKNOWN")
                            }
                        );
                    }
                }
            }
            Ok(Event::End(ref e)) => match e.name().into_inner() {
                b"WebhookUrl" => {
                    if let WxWorkMsgField::WebHookUrl = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for WebhookUrl");
                    }
                }
                b"From" => {
                    is_in_from = false;
                    debug!("Parse close for From");
                }
                b"Event" => {
                    is_in_event = false;
                    debug!("Parse close for Event");
                }
                b"Attachment" => {
                    is_in_attachment = false;
                    debug!("Parse close for Attachment");
                }
                b"AppVersion" => {
                    if let WxWorkMsgField::AppVersion = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for AppVersion");
                    }
                }
                b"UserId" => {
                    if is_in_from {
                        if let WxWorkMsgField::FromUserId = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for From.UserId");
                        }
                    }
                }
                b"Name" => {
                    if is_in_from {
                        if let WxWorkMsgField::FromName = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for From.Name");
                        }
                    } else if is_in_attachment {
                        if let WxWorkMsgField::ActionName = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for Attachment.Actions.Name");
                        }
                    }
                }
                b"Value" => {
                    if is_in_attachment {
                        if let WxWorkMsgField::ActionValue = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for Attachment.Actions.Value");
                        }
                    }
                }
                b"CallbackId" => {
                    if is_in_attachment {
                        if let WxWorkMsgField::ActionCallbackId = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for Attachment.CallbackId");
                        }
                    }
                }
                b"Alias" => {
                    if is_in_from {
                        if let WxWorkMsgField::FromAlias = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for From.Alias");
                        }
                    }
                }
                b"EventType" => {
                    if is_in_event {
                        if let WxWorkMsgField::EventType = field_mode {
                            field_mode = WxWorkMsgField::None;
                            debug!("Parse close for Event.EventType");
                        }
                    }
                }
                b"MsgType" => {
                    if let WxWorkMsgField::MsgType = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for MsgType");
                    }
                }
                b"Text" | b"Markdown" => {
                    if let WxWorkMsgField::Content = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for Content");
                    }
                }
                b"ImageUrl" => {
                    if let WxWorkMsgField::ImageUrl = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for ImageUrl");
                    }
                }
                b"MsgId" => {
                    if let WxWorkMsgField::MsgId = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for MsgId");
                    }
                }
                b"GetChatInfoUrl" => {
                    if let WxWorkMsgField::GetChatInfoUrl = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for GetChatInfoUrl");
                    }
                }
                b"PostId" => {
                    if let WxWorkMsgField::PostId = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for PostId");
                    }
                }
                b"ChatId" => {
                    if let WxWorkMsgField::ChatId = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for ChatId");
                    }
                }
                b"ChatType" => {
                    if let WxWorkMsgField::ChatType = field_mode {
                        field_mode = WxWorkMsgField::None;
                        debug!("Parse close for ChatType");
                    }
                }
                any => {
                    debug!(
                        "Ignore close label for {}",
                        if let Ok(x) = String::from_utf8(any.to_vec()) {
                            x
                        } else {
                            String::from("UNKNOWN")
                        }
                    );
                }
            },
            Ok(Event::CData(data)) => {
                if let WxWorkMsgField::None = field_mode {
                    continue;
                }

                let data_str_opt = match String::from_utf8(Vec::from(data.into_inner())) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        error!("decode Encrypt as utf8 failed, {:?}", e);
                        None
                    }
                };

                let data_str = if let Some(x) = data_str_opt {
                    x
                } else {
                    continue;
                };

                setter_fn(data_str, field_mode);
            }
            Ok(Event::Text(data)) => {
                if let WxWorkMsgField::None = field_mode {
                    continue;
                }

                let data_str_opt = match String::from_utf8(Vec::from(data.into_inner())) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        error!("decode Encrypt as utf8 failed, {:?}", e);
                        None
                    }
                };

                let data_str = if let Some(x) = data_str_opt {
                    x
                } else {
                    continue;
                };

                setter_fn(data_str, field_mode);
            }

            Err(e) => error!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => {}
        }
    }

    let web_hook_key = if let Some(caps) = PICK_WEBHOOK_KEY_RULE.captures(web_hook_url.as_str()) {
        if let Some(x) = caps.name("KEY") {
            String::from(x.as_str())
        } else {
            String::default()
        }
    } else {
        String::default()
    };

    if web_hook_key.is_empty() {
        error!("We can not get robot key from {}", web_hook_url);
    }

    if !image_url.is_empty() && !content.is_empty() {
        msg_type = String::from("mixed");
    }

    Some(WxWorkMessageNtf {
        web_hook_key,
        web_hook_url,
        from: WxWorkMessageFrom {
            user_id: from_user_id,
            name: from_name,
            alias: from_alias,
        },
        msg_type,
        content,
        image_url,
        msg_id,
        post_id,
        chat_id,
        chat_type,
        get_chat_info_url,
        app_version,
        event_type,
        action_name,
        action_value,
        action_callbackid,
    })
}

pub fn pack_text_message(msg: WxWorkMessageTextRsp) -> Result<String, String> {
    debug!("{:?}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if writer
        .write_event(Event::Start(BytesStart::new("xml")))
        .is_ok()
    {
        if writer
            .write_event(Event::Start(BytesStart::new("MsgType")))
            .is_ok()
        {
            let _ = writer.write_event(Event::Text(BytesText::new("text")));
            let _ = writer.write_event(Event::End(BytesEnd::new("MsgType")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("Text")))
            .is_ok()
        {
            if writer
                .write_event(Event::Start(BytesStart::new("Content")))
                .is_ok()
            {
                let _ = writer.write_event(Event::CData(BytesCData::new(
                    quick_xml::escape::escape(msg.content.as_str()),
                )));
                let _ = writer.write_event(Event::End(BytesEnd::new("Content")));
            }

            if writer
                .write_event(Event::Start(BytesStart::new("MentionedList")))
                .is_ok()
            {
                for v in msg.mentioned_list {
                    if writer
                        .write_event(Event::Start(BytesStart::new("Item")))
                        .is_ok()
                    {
                        let _ = writer.write_event(Event::CData(BytesCData::new(
                            quick_xml::escape::escape(v.as_str()),
                        )));
                        let _ = writer.write_event(Event::End(BytesEnd::new("Item")));
                    }
                }
                let _ = writer.write_event(Event::End(BytesEnd::new("MentionedList")));
            }

            if writer
                .write_event(Event::Start(BytesStart::new("MentionedMobileList")))
                .is_ok()
            {
                for v in msg.mentioned_mobile_list {
                    if writer
                        .write_event(Event::Start(BytesStart::new("Item")))
                        .is_ok()
                    {
                        let _ = writer.write_event(Event::CData(BytesCData::new(
                            quick_xml::escape::escape(v.to_string().as_str()),
                        )));
                        let _ = writer.write_event(Event::End(BytesEnd::new("Item")));
                    }
                }
                let _ = writer.write_event(Event::End(BytesEnd::new("MentionedMobileList")));
            }

            let _ = writer.write_event(Event::End(BytesEnd::new("Text")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::new("xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => Ok(ret),
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub fn pack_markdown_message(msg: WxWorkMessageMarkdownRsp) -> Result<String, String> {
    debug!("{:?}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if writer
        .write_event(Event::Start(BytesStart::new("xml")))
        .is_ok()
    {
        if writer
            .write_event(Event::Start(BytesStart::new("MsgType")))
            .is_ok()
        {
            let _ = writer.write_event(Event::Text(BytesText::new("markdown")));
            let _ = writer.write_event(Event::End(BytesEnd::new("MsgType")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("Markdown")))
            .is_ok()
        {
            if writer
                .write_event(Event::Start(BytesStart::new("Content")))
                .is_ok()
            {
                // BytesText::from_escaped_str
                let _ = writer.write_event(Event::CData(BytesCData::new(
                    quick_xml::escape::escape(msg.content.as_str()),
                )));
                let _ = writer.write_event(Event::End(BytesEnd::new("Content")));
            }

            let _ = writer.write_event(Event::End(BytesEnd::new("Markdown")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::new("xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => Ok(ret),
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub fn pack_image_message(msg: WxWorkMessageImageRsp) -> Result<String, String> {
    debug!("{:?}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if writer
        .write_event(Event::Start(BytesStart::new("xml")))
        .is_ok()
    {
        if writer
            .write_event(Event::Start(BytesStart::new("MsgType")))
            .is_ok()
        {
            let _ = writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                "image",
            ))));
            let _ = writer.write_event(Event::End(BytesEnd::new("MsgType")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("Image")))
            .is_ok()
        {
            if writer
                .write_event(Event::Start(BytesStart::new("Base64")))
                .is_ok()
            {
                // BytesText::from_escaped_str
                let _ =
                    writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                        match base64::STANDARD.encode(&msg.content) {
                            Ok(x) => x,
                            Err(e) => e.message,
                        }
                        .as_str(),
                    ))));
                let _ = writer.write_event(Event::End(BytesEnd::new("Base64")));
            }

            let mut hasher = Md5::new();
            hasher.update(&msg.content);

            if writer
                .write_event(Event::Start(BytesStart::new("Md5")))
                .is_ok()
            {
                // BytesText::from_escaped_str
                let _ = writer.write_event(Event::CData(BytesCData::new(
                    quick_xml::escape::escape(hex::encode(hasher.finalize().as_slice()).as_str()),
                )));
                let _ = writer.write_event(Event::End(BytesEnd::new("Md5")));
            }

            let _ = writer.write_event(Event::End(BytesEnd::new("Image")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::new("xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => Ok(ret),
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub fn pack_message_response(
    encrypt: String,
    msg_signature: String,
    timestamp: String,
    nonce: String,
) -> Result<String, String> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if writer
        .write_event(Event::Start(BytesStart::new("xml")))
        .is_ok()
    {
        if writer
            .write_event(Event::Start(BytesStart::new("Encrypt")))
            .is_ok()
        {
            let _ = writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                encrypt.as_str(),
            ))));
            let _ = writer.write_event(Event::End(BytesEnd::new("Encrypt")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("MsgSignature")))
            .is_ok()
        {
            let _ = writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                msg_signature.as_str(),
            ))));
            let _ = writer.write_event(Event::End(BytesEnd::new("MsgSignature")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("TimeStamp")))
            .is_ok()
        {
            let _ = writer.write_event(Event::Text(BytesText::new(timestamp.as_str())));
            let _ = writer.write_event(Event::End(BytesEnd::new("TimeStamp")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("Nonce")))
            .is_ok()
        {
            let _ = writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                nonce.as_str(),
            ))));
            let _ = writer.write_event(Event::End(BytesEnd::new("Nonce")));
        }

        let _ = writer.write_event(Event::End(BytesEnd::new("xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => {
            debug!("packed encrypted message success\n{}", ret);
            Ok(ret)
        }
        Err(e) => {
            error!("packed encrypted message failed: {:?}", e);
            Err(format!("{:?}", e))
        }
    }
}

pub fn get_robot_response_access_deny_content(msg: &str) -> String {
    error!("[Response Error]: {}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if writer
        .write_event(Event::Start(BytesStart::new("xml")))
        .is_ok()
    {
        if writer
            .write_event(Event::Start(BytesStart::new("message")))
            .is_ok()
        {
            let _ = writer.write_event(Event::CData(BytesCData::new(quick_xml::escape::escape(
                msg,
            ))));
            let _ = writer.write_event(Event::End(BytesEnd::new("message")));
        }

        if writer
            .write_event(Event::Start(BytesStart::new("code")))
            .is_ok()
        {
            let _ = writer.write_event(Event::Text(BytesText::new("Access Deny")));
            let _ = writer.write_event(Event::End(BytesEnd::new("code")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::new("xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => ret,
        Err(e) => format!("{:?}", e),
    }
}

pub fn get_robot_response_access_deny(msg: String) -> String {
    get_robot_response_access_deny_content(msg.as_str())
}

pub fn make_robot_error_response_content(msg: &str) -> HttpResponse {
    HttpResponse::Forbidden()
        .content_type("application/xml")
        .body(get_robot_response_access_deny_content(msg))
}

pub fn make_robot_error_response(msg: String) -> HttpResponse {
    make_robot_error_response_content(msg.as_str())
}

pub fn make_robot_not_found_response_content(msg: &str) -> HttpResponse {
    HttpResponse::NotFound()
        .content_type("application/xml")
        .body(get_robot_response_access_deny_content(msg))
}

pub fn make_robot_not_found_response(msg: String) -> HttpResponse {
    make_robot_not_found_response_content(msg.as_str())
}

pub fn make_robot_empty_response() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[cfg(test)]
mod tests {

    use super::*;

    const WXWORKROBOT_TEST_MSG: &str = "<xml><From><UserId><![CDATA[T56650002A]]></UserId><Name><![CDATA[欧文韬]]></Name><Alias><![CDATA[owentou]]></Alias></From><WebhookUrl><![CDATA[http://in.qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxxxxxx]]></WebhookUrl><ChatId><![CDATA[fakechatid]]></ChatId><PostId><![CDATA[fakepostid]]></PostId><GetChatInfoUrl><![CDATA[http://in.qyapi.weixin.qq.com/cgi-bin/webhook/get_chat_info?code=VcgjNN2bHMhatXwG8aZbHvj_RZmLF0OSS5_sVGxYUGk]]></GetChatInfoUrl><MsgId><![CDATA[CIGABBCOgP3qBRiR4vm7goCAAyAY]]></MsgId><ChatType><![CDATA[group]]></ChatType><MsgType><![CDATA[text]]></MsgType><Text><Content><![CDATA[@fa机器人 help]]></Content></Text></xml>";
    const WXWORKROBOT_TEST_MSG_WITH_KNOWN_DATA: &str = "<xml><unknown_field1><![CDATA[blablabla]]></unknown_field1><From><UserId><![CDATA[T56650002A]]></UserId><Name><![CDATA[欧文韬]]></Name><Alias><![CDATA[owentou]]></Alias></From><WebhookUrl><![CDATA[http://in.qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxxxxxx]]></WebhookUrl><ChatId><![CDATA[fakechatid]]></ChatId><PostId><![CDATA[fakepostid]]></PostId><unknown_field2>test_message</unknown_field2><GetChatInfoUrl><![CDATA[http://in.qyapi.weixin.qq.com/cgi-bin/webhook/get_chat_info?code=VcgjNN2bHMhatXwG8aZbHvj_RZmLF0OSS5_sVGxYUGk]]></GetChatInfoUrl><MsgId><![CDATA[CIGABBCOgP3qBRiR4vm7goCAAyAY]]></MsgId><ChatType><![CDATA[group]]></ChatType><MsgType><![CDATA[text]]></MsgType><Text><Content><![CDATA[@fa机器人 help]]></Content></Text></xml>";

    #[test]
    fn decode_wxwork_robot_msg() {
        let decode_res = get_msg_from_str(WXWORKROBOT_TEST_MSG);
        assert!(decode_res.is_some());
        if let Some(msg) = decode_res {
            assert_eq!(msg.content, "@fa机器人 help");
            assert_eq!(msg.from.user_id, "T56650002A");
            assert_eq!(msg.from.name, "欧文韬");
            assert_eq!(msg.from.alias, "owentou");
            assert_eq!(msg.msg_id, "CIGABBCOgP3qBRiR4vm7goCAAyAY");
            assert_eq!(msg.msg_type, "text");
            assert_eq!(msg.post_id, "fakepostid");
            assert_eq!(msg.chat_id, "fakechatid");
            assert_eq!(msg.chat_type, "group");
            assert!(msg.event_type.is_empty());
            assert!(msg.action_name.is_empty());
            assert!(msg.action_value.is_empty());
            assert!(msg.action_callbackid.is_empty());
        }
    }

    #[test]
    fn decode_wxwork_robot_msg_with_known_fields() {
        let decode_res = get_msg_from_str(WXWORKROBOT_TEST_MSG_WITH_KNOWN_DATA);
        assert!(decode_res.is_some());
        if let Some(msg) = decode_res {
            assert_eq!(msg.content, "@fa机器人 help");
            assert_eq!(msg.from.user_id, "T56650002A");
            assert_eq!(msg.from.name, "欧文韬");
            assert_eq!(msg.from.alias, "owentou");
            assert_eq!(msg.msg_id, "CIGABBCOgP3qBRiR4vm7goCAAyAY");
            assert_eq!(msg.msg_type, "text");
            assert_eq!(msg.post_id, "fakepostid");
            assert_eq!(msg.chat_id, "fakechatid");
            assert_eq!(msg.chat_type, "group");
            assert!(msg.event_type.is_empty());
            assert!(msg.action_name.is_empty());
            assert!(msg.action_value.is_empty());
            assert!(msg.action_callbackid.is_empty());
        }
    }
    const WXWORKROBOT_TEST_MSG_EVENT: &str = r#"<xml>
        <WebhookUrl> <![CDATA[https://qyapi.weixin.qq.com/xxxxxxx]]></WebhookUrl>
        <PostId><![CDATA[bpkSFfCgAAWeiHos2p6lJbG3_F2xxxxx]]></PostId>
        <ChatId><![CDATA[wrkSFfCgAALFgnrSsWU38puiv4yvExuw]]></ChatId>
        <ChatType>single</ChatType>
        <GetChatInfoUrl><![CDATA[https://qyapi.weixin.qq.com/cgi-bin/webhook/get_chat_info?code=m49c5aRCdEP8_QQdZmTNR52yJ5TLGcIMzaLJk3x5KqY]]></GetChatInfoUrl>
        <From>
            <UserId>zhangsan</UserId>
            <Name><![CDATA[张三]]></Name>
            <Alias><![CDATA[jackzhang]]></Alias>
        </From>
        <MsgType>event</MsgType>
        <Event>
            <EventType><![CDATA[add_to_chat]]></EventType>
        </Event>
        <AppVersion><![CDATA[2.8.12.1551]]></AppVersion>
        <MsgId>abcdabcdabcd</MsgId>
    </xml>"#;

    #[test]
    fn decode_wxwork_robot_msg_event() {
        let decode_res = get_msg_from_str(WXWORKROBOT_TEST_MSG_EVENT);
        assert!(decode_res.is_some());
        if let Some(msg) = decode_res {
            assert!(msg.content.is_empty());
            assert_eq!(msg.from.user_id, "zhangsan");
            assert_eq!(msg.from.name, "张三");
            assert_eq!(msg.from.alias, "jackzhang");
            assert_eq!(msg.msg_id, "abcdabcdabcd");
            assert_eq!(msg.msg_type, "event");
            assert_eq!(msg.post_id, "bpkSFfCgAAWeiHos2p6lJbG3_F2xxxxx");
            assert_eq!(msg.chat_id, "wrkSFfCgAALFgnrSsWU38puiv4yvExuw");
            assert_eq!(msg.chat_type, "single");
            assert_eq!(msg.event_type, "add_to_chat");
            assert_eq!(msg.app_version, "2.8.12.1551");
            assert!(msg.action_name.is_empty());
            assert!(msg.action_value.is_empty());
            assert!(msg.action_callbackid.is_empty());
        }
    }

    const WXWORKROBOT_TEST_MSG_ATTACHMENT: &str = r#"<xml>
        <WebhookUrl><![CDATA[http://in.qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxx]]></WebhookUrl>
        <PostId><![CDATA[yyyyy]]></PostId>
        <ChatId><![CDATA[xxxxx]]></ChatId>
        <ChatType>single</ChatType>
        <From>
            <UserId><![CDATA[zhangsan]]></UserId>
            <Name><![CDATA[张三]]></Name>
            <Alias><![CDATA[zhangsan]]></Alias>
        </From>
        <MsgId><![CDATA[xxxxx]]></MsgId>
        <MsgType><![CDATA[attachment]]></MsgType>
        <Attachment>
            <CallbackId><![CDATA[check_more]]></CallbackId>
            <Actions>
                <Name><![CDATA[button_more]]></Name>
                <Value><![CDATA[button_more]]></Value>
            </Actions>
        </Attachment>
    </xml>"#;

    #[test]
    fn decode_wxwork_robot_msg_attachment() {
        let decode_res = get_msg_from_str(WXWORKROBOT_TEST_MSG_ATTACHMENT);
        assert!(decode_res.is_some());
        if let Some(msg) = decode_res {
            assert!(msg.content.is_empty());
            assert_eq!(msg.from.user_id, "zhangsan");
            assert_eq!(msg.from.name, "张三");
            assert_eq!(msg.from.alias, "zhangsan");
            assert_eq!(msg.msg_id, "xxxxx");
            assert_eq!(msg.msg_type, "attachment");
            assert_eq!(msg.post_id, "yyyyy");
            assert_eq!(msg.chat_id, "xxxxx");
            assert_eq!(msg.chat_type, "single");
            assert!(msg.event_type.is_empty());
            assert_eq!(msg.action_name, "button_more");
            assert_eq!(msg.action_value, "button_more");
            assert_eq!(msg.action_callbackid, "check_more");
        }
    }
}
