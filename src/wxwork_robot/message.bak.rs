use base64;
use data_encoding::BASE64_NOPAD;
use crypto::aes::cbc_decryptor;
use crypto::symmetriccipher::Decryptor;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

static REPLAY_MSG_TEXT_TEMPLATE: &str = "<xml>
    <MsgType>text</MsgType>
    <Text>
        <Content>![CDATA[hello\nI'm RobotA\n]]</Content>
        <MentionedList>
            <Item>![CDATA[zhangsan]]</Item>
            <Item>![CDATA[@all]]</Item>
        </MentionedList>
        <MentionedMobileList>
            <Item>![CDATA[@all]]</Item>
            <Item>![CDATA[1380000000]]</Item>
        </MentionedMobileList>
    </Text>
</xml>";

static REPLAY_MSG_MARKDOWN_TEMPLATE: &str = "<xml>
    <MsgType>markdown</MsgType>
    <Markdown>
        <Content>![CDATA[实时新增用户反馈<font color=\"warning\">132例</font>，请相关同事注意。\n>类型:<font color=\"comment\">用户反馈</font> \n>普通用户反馈:<font color=\"comment\">117例</font> \n >VIP用户反馈:<font color=\"comment\">15例</font>]]</Content>
    </Markdown>
</xml>";

static REPLAY_MSG_RESPONSE_TEMPLATE: &str = "<xml>
    <Encrypt><![CDATA[msg_encrypt]]></Encrypt>
    <MsgSignature><![CDATA[msg_signature]]></MsgSignature>
    <TimeStamp>timestamp</TimeStamp>
    <Nonce><![CDATA[nonce]]></Nonce>
</xml>";

static REPLAY_MSG_REQUEST_TEMPLATE: &str = "<xml>
    <WebhookUrl> ![CDATA[https://qyapi.weixin.qq.com/xxxxxxx]]</WebhookUrl>
    <From>
        <UserId>zhangsan</UserId>
        <Name>![CDATA[张三]]</Name>
        <Alias>![CDATA[jackzhang]]</Alias>
    </From>
    <MsgType>text</MsgType>
    <Text>
        <Content>![CDATA[@RobotA hello robot]]</Content>
    </Text>
    <MsgId>abcdabcdabcd</MsgId>
</xml>";

#[derive(Debug, Clone)]
pub enum WXWorkMessageType {
    TEXT,
    MARKDOWN
};

#[derive(Debug, Clone)]
pub struct WXWorkUser {
    pub id: String,
    pub name: String,
    pub alias: String,
};

#[derive(Debug, Clone)]
pub struct WXWorkMessage {
    pub token: String,
    pub timestamp: i64,
    pub nonce: u64,
    pub content: String,
    pub receiveid: String,
    pub id: String,
    pub type: WXWorkMessageType,
    pub from: Option<WXWorkUser>,
    pub mentioned_list: Vec<String>,
};


// msg_signature： 消息签名，用于验证请求是否来自企业微信（防止攻击者伪造）。
// EncodingAESKey：用于消息体的加密，长度固定为43个字符，从a-z, A-Z, 0-9共62个字符中选取，是AESKey的Base64编码。解码后即为32字节长的AESKey
//
//   AESKey=Base64_Decode(EncodingAESKey + “=”)
//
// AESKey：AES算法的密钥，长度为32字节。
// AES采用CBC模式，数据采用PKCS#7填充至32字节的倍数；IV初始向量大小为16字节，取AESKey前16字节，详见：http://tools.ietf.org/html/rfc2315
// msg：为消息体明文，格式为XML
// msg_encrypt：明文消息msg加密处理后的Base64编码。

pub fn msg_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    msg_encrypt: &str
) -> String {
    // GET http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323&echostr=ENCRYPT_STR
    // dev_msg_signature=sha1(sort(token、timestamp、nonce、msg_encrypt))
    // sort的含义是将参数值按照字母字典排序，然后从小到大拼接成一个字符串
    // sha1处理结果要编码为可见字符，编码的方式是把每字节散列值打印为%02x（即16进制，C printf语法）格式，全部小写
    String::from("")
}

pub fn check_msg_signature(
    excepted_signature: &str,
    token: &str,
    timestamp: &str,
    nonce: &str,
    msg_encrypt: &str) {
    let real_signature = msg_signature(token, timestamp, nonce, msg_encrypt);
    if (real_signature.as_str() == excepted_signature) {
        true
    } else {
        error!("[ROBOT]: Check signature failed, except {0}, reas is {1}", excepted_signature, real_signature);
        false
    }
}

pub fn encrypt_msg(
    token: &str,
    timestamp: i64,
    nonce: u64,
    msg_encrypt: &str
) -> String {
    // rand_msg = random(16B) + msg_len(4B) + msg + receiveid
    // 明文字符串由16个字节的随机字符串、4个字节的msg长度、明文msg和receiveid拼接组成。其中msg_len为msg的字节数，网络字节序；sReceiveId 在不同场景下有不同含义
    // receiveid直接传空字符串即可
    String::from("")
}

pub fn encrypt_msg_base64(
    token: &str,
    timestamp: i64,
    nonce: u64,
    msg_encrypt: &str
) -> String {
    // msg_encrypt = Base64_Encode(AES_Encrypt(rand_msg))
    String::from("")
}

pub fn decrypt_msg_raw(input: &[u8], mut dec: &Decryptor) -> Result<[u8], ()> {
    // rand_msg=AES_Decrypt(aes_msg)
    // 去掉rand_msg头部的16个随机字节和4个字节的msg_len，截取msg_len长度的部分即为msg，剩下的为尾部的receiveid
    // 网络字节序
    let mut ret = input.clone();
    dec.decrypt(RefReadBuffer::new(input), RefWriteBuffer::new(ret), true);
    Ok(ret)
}

pub fn decrypt_msg_raw_base64(input: &str, mut dec: &Decryptor) -> Result<[u8], ()> {
    // POST http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323
    // aes_msg=Base64_Decode(msg_encrypt)
    let bin = base64::decode_config(input, base64::STANDARD_NO_PAD)?;
    decrypt_msg_raw(bin, aes_token)
}

pub fn decrypt_msg(input: &[u8], aes_token: &str) -> Result<WXWorkMessage, ()> {
    // rand_msg=AES_Decrypt(aes_msg)
    // 去掉rand_msg头部的16个随机字节和4个字节的msg_len，截取msg_len长度的部分即为msg，剩下的为尾部的receiveid
    // 网络字节序
}

pub fn decrypt_msg_base64(input: &str, aes_token: &str) -> Result<WXWorkMessage, ()> {
    // POST http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323
    // aes_msg=Base64_Decode(msg_encrypt)
    let bin = base64::decode_config(input, base64::STANDARD_NO_PAD)?;
    decrypt_msg(bin, aes_token)
}