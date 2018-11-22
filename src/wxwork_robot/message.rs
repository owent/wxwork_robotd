use bytes::buf::IntoBuf;
use bytes::Bytes;
// use hex;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Reader;
use quick_xml::Writer;
use std::io::Cursor;

use actix_web::HttpResponse;

#[derive(Debug, Clone)]
pub struct WXWorkMessageDec {
    pub content: String,
    pub receiveid: String,
}

#[derive(Debug, Clone)]
pub struct WXWorkMessageFrom {
    pub user_id: String,
    pub name: String,
    pub alias: String,
}

#[derive(Debug, Clone)]
pub struct WXWorkMessageNtf {
    pub web_hook_url: String,
    pub from: WXWorkMessageFrom,
    pub msg_type: String,
    pub content: String,
    pub msg_id: String,
}

#[derive(Debug, Clone)]
pub struct WXWorkMessageTextRsp {
    pub content: String,
    pub mentioned_list: Vec<String>,
    pub mentioned_mobile_list: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct WXWorkMessageMarkdownRsp {
    pub content: String,
}

pub fn get_msg_encrypt_from_bytes(bytes: Bytes) -> Option<String> {
    let mut reader = Reader::from_reader(bytes.into_buf());
    reader.trim_text(true);
    let mut is_msg_field = false;
    let mut ret = None;
    let mut buf = Vec::new();
    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name() {
                b"Encrypt" => {
                    is_msg_field = true;
                }
                _ => (),
            },
            Ok(Event::End(ref e)) => match e.name() {
                b"Encrypt" => {
                    is_msg_field = false;
                }
                _ => (),
            },
            Ok(Event::CData(data)) => {
                if is_msg_field {
                    if let Ok(x) = data.unescaped() {
                        match String::from_utf8(Vec::from(x)) {
                            Ok(s) => {
                                ret = Some(s);
                            }
                            Err(e) => {
                                error!("decode Encrypt as utf8 failed, {:?}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => error!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    ret
}

enum WXWorkMsgField {
    NONE,
    WebHookUrl,
    FromUserId,
    FromName,
    FromAlias,
    MsgType,
    Content,
    MsgId,
}

pub fn get_msg_from_str(input: &str) -> Option<WXWorkMessageNtf> {
    let mut web_hook_url = String::default();
    let mut from_user_id = String::default();
    let mut from_name = String::default();
    let mut from_alias = String::default();
    let mut msg_type = String::default();
    let mut content = String::default();
    let mut msg_id = String::default();
    let mut is_in_from = false;
    let mut field_mode = WXWorkMsgField::NONE;

    let mut reader = Reader::from_str(input);
    reader.trim_text(true);

    let mut buf = Vec::new();
    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name() {
                b"WebhookUrl" => {
                    field_mode = WXWorkMsgField::WebHookUrl;
                }
                b"From" => {
                    is_in_from = true;
                }
                b"UserId" => {
                    if is_in_from {
                        field_mode = WXWorkMsgField::FromUserId;
                    }
                }
                b"Name" => {
                    if is_in_from {
                        field_mode = WXWorkMsgField::FromName;
                    }
                }
                b"Alias" => {
                    if is_in_from {
                        field_mode = WXWorkMsgField::FromAlias;
                    }
                }
                b"MsgType" => {
                    field_mode = WXWorkMsgField::MsgType;
                }
                b"Text" | b"Markdown" => {
                    field_mode = WXWorkMsgField::Content;
                }
                b"MsgId" => {
                    field_mode = WXWorkMsgField::MsgId;
                }
                _ => (),
            },
            Ok(Event::End(ref e)) => match e.name() {
                b"WebhookUrl" => {
                    if let WXWorkMsgField::WebHookUrl = field_mode {
                        field_mode = WXWorkMsgField::NONE;
                    }
                }
                b"From" => {
                    is_in_from = false;
                }
                b"UserId" => {
                    if is_in_from {
                        if let WXWorkMsgField::FromUserId = field_mode {
                            field_mode = WXWorkMsgField::NONE;
                        }
                    }
                }
                b"Name" => {
                    if is_in_from {
                        if let WXWorkMsgField::FromName = field_mode {
                            field_mode = WXWorkMsgField::NONE;
                        }
                    }
                }
                b"Alias" => {
                    if is_in_from {
                        if let WXWorkMsgField::FromAlias = field_mode {
                            field_mode = WXWorkMsgField::NONE;
                        }
                    }
                }
                b"MsgType" => {
                    if let WXWorkMsgField::MsgType = field_mode {
                        field_mode = WXWorkMsgField::NONE;
                    }
                }
                b"Text" | b"Markdown" => {
                    if let WXWorkMsgField::Content = field_mode {
                        field_mode = WXWorkMsgField::NONE;
                    }
                }
                b"MsgId" => {
                    if let WXWorkMsgField::MsgId = field_mode {
                        field_mode = WXWorkMsgField::NONE;
                    }
                }
                _ => (),
            },
            Ok(Event::CData(data)) | Ok(Event::Text(data)) => {
                if let WXWorkMsgField::NONE = field_mode {
                    break;
                }

                let data_str_opt = if let Ok(x) = data.unescaped() {
                    match String::from_utf8(Vec::from(x)) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            error!("decode Encrypt as utf8 failed, {:?}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let data_str = if let Some(x) = data_str_opt {
                    x
                } else {
                    break;
                };

                match field_mode {
                    WXWorkMsgField::WebHookUrl => {
                        web_hook_url = data_str;
                    }
                    WXWorkMsgField::FromUserId => {
                        from_user_id = data_str;
                    }
                    WXWorkMsgField::FromName => {
                        from_name = data_str;
                    }
                    WXWorkMsgField::FromAlias => {
                        from_alias = data_str;
                    }
                    WXWorkMsgField::MsgType => {
                        msg_type = data_str;
                    }
                    WXWorkMsgField::Content => {
                        content = data_str;
                    }
                    WXWorkMsgField::MsgId => {
                        msg_id = data_str;
                    }
                    _ => {}
                }
            }
            Err(e) => error!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    Some(WXWorkMessageNtf {
        web_hook_url: web_hook_url,
        from: WXWorkMessageFrom {
            user_id: from_user_id,
            name: from_name,
            alias: from_alias,
        },
        msg_type: msg_type,
        content: content,
        msg_id: msg_id,
    })
}

pub fn pack_text_message(msg: WXWorkMessageTextRsp) -> Result<String, String> {
    debug!("{:?}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"xml"))) {
        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"MsgType"))) {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str("text")));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"MsgType")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Text"))) {
            if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Content"))) {
                let _ = writer.write_event(Event::CData(BytesText::from_plain_str(
                    msg.content.as_str(),
                )));
                let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Content")));
            }

            if let Ok(_) =
                writer.write_event(Event::Start(BytesStart::borrowed_name(b"MentionedList")))
            {
                for v in msg.mentioned_list {
                    if let Ok(_) =
                        writer.write_event(Event::Start(BytesStart::borrowed_name(b"Item")))
                    {
                        let _ =
                            writer.write_event(Event::CData(BytesText::from_plain_str(v.as_str())));
                        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Item")));
                    }
                }
                let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"MentionedList")));
            }

            if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(
                b"MentionedMobileList",
            ))) {
                for v in msg.mentioned_mobile_list {
                    if let Ok(_) =
                        writer.write_event(Event::Start(BytesStart::borrowed_name(b"Item")))
                    {
                        let _ = writer.write_event(Event::CData(BytesText::from_plain_str(
                            v.to_string().as_str(),
                        )));
                        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Item")));
                    }
                }
                let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"MentionedMobileList")));
            }

            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Text")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"xml")));
    }

    match String::from_utf8(writer.into_inner().into_inner()) {
        Ok(ret) => Ok(ret),
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub fn pack_markdown_message(msg: WXWorkMessageMarkdownRsp) -> Result<String, String> {
    debug!("{:?}", msg);
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"xml"))) {
        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"MsgType"))) {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str("markdown")));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"MsgType")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Markdown"))) {
            if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Content"))) {
                // BytesText::from_escaped_str
                let _ = writer.write_event(Event::CData(BytesText::from_escaped_str(
                    msg.content.as_str(),
                )));
                let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Content")));
            }

            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Markdown")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"xml")));
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

    if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"xml"))) {
        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Encrypt"))) {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str(encrypt.as_str())));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Encrypt")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"MsgSignature")))
        {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str(
                msg_signature.as_str(),
            )));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"MsgSignature")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"TimeStamp"))) {
            let _ = writer.write_event(Event::Text(BytesText::from_plain_str(timestamp.as_str())));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"TimeStamp")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"Nonce"))) {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str(nonce.as_str())));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"Nonce")));
        }

        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"xml")));
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

    if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"xml"))) {
        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"message"))) {
            let _ = writer.write_event(Event::CData(BytesText::from_plain_str(msg)));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"message")));
        }

        if let Ok(_) = writer.write_event(Event::Start(BytesStart::borrowed_name(b"code"))) {
            let _ = writer.write_event(Event::Text(BytesText::from_plain_str("Access Deny")));
            let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"code")));
        }
        let _ = writer.write_event(Event::End(BytesEnd::borrowed(b"xml")));
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
