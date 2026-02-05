use actix_web::HttpResponse;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::cipher::block_padding::NoPadding;
// use cipher::{BlockCipher, NewBlockCipher};
use byteorder::{BigEndian, ByteOrder};

// use openssl::symm::{Cipher, Crypter, Mode};
use ring::rand::SecureRandom;

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::{base64, command, message};

type Aes128CbcEncoder = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDecoder = cbc::Decryptor<aes::Aes256>;

// #[derive(Clone)]
struct WxWorkProjectCipherInfo {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

pub struct WxWorkProject {
    name: Arc<String>,
    pub token: String,
    pub encoding_aes_key: String,
    pub envs: Rc<serde_json::Value>,
    pub cmds: Rc<command::WxWorkCommandList>,
    pub events: Rc<command::WxWorkCommandList>,

    cipher_info: Arc<Mutex<Box<WxWorkProjectCipherInfo>>>,
    nonce: AtomicUsize,
}

unsafe impl Send for WxWorkProject {}
unsafe impl Sync for WxWorkProject {}

pub type WxWorkProjectPtr = Arc<WxWorkProject>;
pub type WxWorkProjectMap = HashMap<String, WxWorkProjectPtr>;

// fn get_block_size<T: BlockCipher + NewBlockCipher>() -> usize {
//     T::BlockSize::to_usize()
// }

impl WxWorkProject {
    pub fn parse(json: &serde_json::Value) -> WxWorkProjectMap {
        let mut ret: HashMap<String, Arc<WxWorkProject>> = HashMap::new();

        if let Some(arr) = json.as_array() {
            for conf in arr {
                let proj_res = WxWorkProject::new(conf);
                if let Some(proj) = proj_res {
                    ret.insert((*proj.name()).clone(), Arc::new(proj));
                }
            }
        }

        ret
    }

    pub fn new(json: &serde_json::Value) -> Option<WxWorkProject> {
        if !json.is_object() {
            error!("project configure invalid: {}", json);
            eprintln!("project configure invalid: {}", json);
            return None;
        }
        let proj_name: String;
        let proj_token: String;
        let proj_aes_key: String;
        let proj_cmds: command::WxWorkCommandList;
        let proj_events: command::WxWorkCommandList;
        let mut envs_obj = json!({});

        {
            if !json.is_object() {
                error!("project must be a json object, but real is {}", json);
                eprintln!("project must be a json object, but real is {}", json);
                return None;
            };

            proj_name = if let Some(x) = command::read_string_from_json_object(json, "name") {
                x
            } else {
                error!("project configure must has name field {}", json);
                eprintln!("project configure must has name field {}", json);
                return None;
            };

            proj_token = if let Some(x) = command::read_string_from_json_object(json, "token") {
                x
            } else {
                error!(
                    "project \"{}\" configure must has token field {}",
                    proj_name, json
                );
                eprintln!(
                    "project \"{}\" configure must has token field {}",
                    proj_name, json
                );
                return None;
            };

            proj_aes_key =
                if let Some(x) = command::read_string_from_json_object(json, "encodingAESKey") {
                    x
                } else {
                    error!(
                        "project \"{}\" configure must has encodingAESKey field {}",
                        proj_name, json
                    );
                    eprintln!(
                        "project \"{}\" configure must has encodingAESKey field {}",
                        proj_name, json
                    );
                    return None;
                };

            let mut envs_var_count = 0;
            if let Some(envs_kvs) = command::read_object_from_json_object(json, "env") {
                for (k, v) in envs_kvs {
                    envs_obj[format!("WXWORK_ROBOT_PROJECT_{}", k)
                        .as_str()
                        .to_uppercase()] = if v.is_string() {
                        v.clone()
                    } else {
                        serde_json::Value::String(v.to_string())
                    };
                    envs_var_count += 1;
                }
            }

            if let Some(kvs) = json.as_object() {
                if let Some(cmds_json) = kvs.get("cmds") {
                    proj_cmds = command::WxWorkCommand::parse(cmds_json);
                } else {
                    proj_cmds = Vec::new();
                }
            } else {
                proj_cmds = Vec::new();
            }

            if let Some(kvs) = json.as_object() {
                if let Some(cmds_json) = kvs.get("events") {
                    proj_events = command::WxWorkCommand::parse(cmds_json);
                } else {
                    proj_events = Vec::new();
                }
            } else {
                proj_events = Vec::new();
            }

            for cmd in proj_cmds.iter() {
                info!(
                    "project \"{}\" load command \"{}\" success",
                    proj_name,
                    cmd.name()
                );
            }
            for cmd in proj_events.iter() {
                info!(
                    "project \"{}\" load event \"{}\" success",
                    proj_name,
                    cmd.name()
                );
            }
            debug!("project \"{}\" with token(base64): \"{}\", aes key(base64): \"{}\" , env vars({}), load success.", proj_name, proj_token, proj_aes_key, envs_var_count);
        }

        envs_obj["WXWORK_ROBOT_PROJECT_NAME"] = serde_json::Value::String(proj_name.clone());
        envs_obj["WXWORK_ROBOT_PROJECT_TOKEN"] = serde_json::Value::String(proj_token.clone());
        envs_obj["WXWORK_ROBOT_PROJECT_ENCODING_AES_KEY"] =
            serde_json::Value::String(proj_aes_key.clone());

        let aes_key_bin = match base64::STANDARD_UTF7.decode(proj_aes_key.as_bytes()) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "project \"{}\" configure encodingAESKey \"{}\" decode failed \"{}\"",
                    proj_name, proj_aes_key, e
                );
                eprintln!(
                    "project \"{}\" configure encodingAESKey \"{}\" decode failed \"{}\"",
                    proj_name, proj_aes_key, e
                );
                return None;
            }
        };

        //let cipher_iv_len = <Aes256 as BlockCipher>::BlockSize::to_usize();
        //let cipher_iv_len = U16::to_usize();
        // According to https://en.wikipedia.org/wiki/Block_size_(cryptography)
        // Block size of AES is always 128bits/16bytes
        let cipher_iv_len: usize = 16;
        let cipher_iv = if aes_key_bin.len() >= cipher_iv_len {
            Vec::from(&aes_key_bin[0..cipher_iv_len])
        } else {
            Vec::new()
        };
        let _ = match Aes128CbcDecoder::new_from_slices(&aes_key_bin, &cipher_iv) {
            Ok(x) => x,
            Err(e) => {
                let err_msg = format!(
                    "project \"{}\" configure encodingAESKey \"{}\" failed, {:?}",
                    proj_name, proj_aes_key, e
                );
                error!("{}", err_msg);
                eprintln!("{}", err_msg);
                return None;
            }
        };

        debug!(
            "project \"{}\" load aes key: \"{}\", iv: \"{}\", block size: {}",
            proj_name,
            hex::encode(&aes_key_bin),
            hex::encode(&cipher_iv),
            cipher_iv_len
        );

        let cipher_info = WxWorkProjectCipherInfo {
            key: aes_key_bin,
            iv: cipher_iv,
        };

        Some(WxWorkProject {
            name: Arc::new(proj_name),
            token: proj_token,
            encoding_aes_key: proj_aes_key,
            envs: Rc::new(envs_obj),
            cmds: Rc::new(proj_cmds),
            events: Rc::new(proj_events),

            cipher_info: Arc::new(Mutex::new(Box::new(cipher_info))),
            nonce: AtomicUsize::new(
                if let Ok(x) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    (x.as_secs() as usize) << 16
                } else {
                    1_usize << 16
                },
            ),
        })
    }

    pub fn name(&self) -> Arc<String> {
        self.name.clone()
    }

    pub fn try_commands(
        &self,
        message: &str,
        allow_hidden: bool,
    ) -> Option<(command::WxWorkCommandPtr, command::WxWorkCommandMatch)> {
        WxWorkProject::try_capture_commands(&self.cmds, message, allow_hidden)
    }

    pub fn try_events(
        &self,
        message: &str,
        allow_hidden: bool,
    ) -> Option<(command::WxWorkCommandPtr, command::WxWorkCommandMatch)> {
        WxWorkProject::try_capture_commands(&self.events, message, allow_hidden)
    }

    pub fn try_capture_commands(
        cmds: &[command::WxWorkCommandPtr],
        message: &str,
        allow_hidden: bool,
    ) -> Option<(command::WxWorkCommandPtr, command::WxWorkCommandMatch)> {
        for cmd in cmds {
            // empty message must equal
            if cmd.name().is_empty() && !message.is_empty() {
                continue;
            }

            if !allow_hidden {
                // skip hidden command
                if cmd.is_hidden() {
                    continue;
                }
            }
            let mat_res = cmd.try_capture(message);
            if mat_res.has_result() {
                return Some((cmd.clone(), mat_res));
            }
        }

        None
    }

    pub fn generate_template_vars(
        &self,
        cmd_match: &command::WxWorkCommandMatch,
    ) -> serde_json::Value {
        let mut ret = self.envs.as_ref().clone();
        ret = command::merge_envs(ret, cmd_match.ref_json());

        ret
    }

    #[allow(unused)]
    pub fn pkcs7_encode(&self, input: &[u8]) -> Vec<u8> {
        let block_size: usize = 32;
        let mut ret = Vec::new();

        let text_length = input.len();
        let padding_length = match block_size - text_length % block_size {
            0 => block_size,
            x => x,
        };
        let padding_char: u8 = padding_length as u8;

        ret.reserve(text_length + padding_length);
        ret.extend_from_slice(input);
        ret.extend(std::iter::repeat_n(padding_char, padding_length));

        ret
    }

    #[allow(unused)]
    pub fn pkcs7_decode<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        let block_size: usize = 32;

        if input.is_empty() {
            return input;
        }

        let padding_char = input[input.len() - 1];
        if padding_char < 1 || padding_char as usize > block_size {
            return input;
        }

        &input[0..(input.len() - padding_char as usize)]
    }

    pub fn decrypt_msg_raw(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        // rand_msg=AES_Decrypt(aes_msg)
        // 去掉rand_msg头部的16个随机字节和4个字节的msg_len，截取msg_len长度的部分即为msg，剩下的为尾部的receiveid
        // 网络字节序

        // let block_size: usize;

        let decrypter = match self.cipher_info.lock() {
            Ok(c) => {
                let ci = &*c;
                match Aes128CbcDecoder::new_from_slices(&ci.key, &ci.iv) {
                    Ok(x) => x,
                    Err(e) => {
                        let ret = format!(
                            "project \"{}\" try to create aes256 decrypter failed, {:?}",
                            self.name(),
                            e
                        );
                        error!("{}", ret);
                        return Err(ret);
                    }
                }
            }
            Err(e) => {
                let ret = format!(
                    "project \"{}\" try to lock cipher_info failed, {:?}",
                    self.name(),
                    e
                );
                error!("{}", ret);
                return Err(ret);
            }
        };

        let mut buf = input.to_vec();
        match decrypter.decrypt_padded_mut::<NoPadding>(&mut buf) {
            Ok(x) => Ok(x.to_vec()),
            Err(e) => {
                let ret = format!("project \"{}\" try to decrypt failed, {:?}", self.name(), e);
                error!("{}", ret);
                Err(ret)
            }
        }

        /*
        decrypter.pad(false);
        let mut plaintext = vec![0; input.len() + block_size];
        let mut plaintext_count = match decrypter.update(input, &mut plaintext) {
            Ok(x) => x,
            Err(e) => {
                let ret = format!(
                    "project \"{}\" decrypt {} update failed\n{:?}",
                    self.name(),
                    hex::encode(input),
                    e
                );
                debug!("{}", ret);
                return Err(ret);
            }
        };

        plaintext_count += match decrypter.finalize(&mut plaintext[plaintext_count..]) {
            Ok(x) => x,
            Err(e) => {
                let ret = format!(
                    "project \"{}\" decrypt {} finalize failed\n{:?}",
                    self.name(),
                    hex::encode(input),
                    e
                );
                debug!("{}", ret);
                return Err(ret);
            }
        };

        plaintext.truncate(plaintext_count);
        Ok(plaintext)
        */
    }

    pub fn decrypt_msg_raw_base64(&self, input: &str) -> Result<Vec<u8>, String> {
        // POST http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323
        // aes_msg=Base64_Decode(msg_encrypt)
        let bin = match base64::STANDARD.decode(input.as_bytes()) {
            Ok(x) => x,
            Err(e) => {
                let ret = format!(
                    "project \"{}\" decode base64 {} failed, {:?}",
                    self.name(),
                    input,
                    e.to_string()
                );
                error!("{}", ret);
                return Err(ret);
            }
        };

        match self.decrypt_msg_raw(&bin) {
            Ok(x) => Ok(x),
            Err(e) => Err(e),
        }
    }

    pub fn decrypt_msg_raw_base64_content(
        &self,
        input: &str,
    ) -> Result<message::WxWorkMessageDec, String> {
        let dec_bin = match self.decrypt_msg_raw_base64(input) {
            Ok(x) => x,
            Err(e) => {
                return Err(e);
            }
        };

        debug!(
            "project \"{}\" try to decrypt base64: {}",
            self.name(),
            input
        );
        let dec_bin_unpadding = self.pkcs7_decode(&dec_bin);

        if dec_bin_unpadding.len() <= 20 {
            let err_msg = format!(
                "project \"{}\" decode {} data length invalid",
                self.name(),
                hex::encode(dec_bin_unpadding)
            );
            error!("{}", err_msg);
            return Err(err_msg);
        }

        let msg_len = BigEndian::read_u32(&dec_bin_unpadding[16..20]) as usize;
        if msg_len + 20 > dec_bin_unpadding.len() {
            let err_msg = format!(
                "project \"{}\" decode message length {} , but bin data {} has only length {}",
                self.name(),
                msg_len,
                hex::encode(dec_bin_unpadding),
                dec_bin_unpadding.len()
            );
            error!("{}", err_msg);
            return Err(err_msg);
        }

        let msg_content = match String::from_utf8(dec_bin_unpadding[20..(20 + msg_len)].to_vec()) {
            Ok(x) => x,
            Err(e) => {
                let err_msg = format!(
                    "project \"{}\" decode message content {} failed, {:?}",
                    self.name(),
                    hex::encode(&dec_bin_unpadding[20..msg_len]),
                    e
                );
                error!("{}", err_msg);
                return Err(err_msg);
            }
        };

        let receiveid = if dec_bin_unpadding.len() > 20 + msg_len {
            match String::from_utf8(dec_bin_unpadding[(20 + msg_len)..].to_vec()) {
                Ok(x) => x,
                Err(e) => {
                    let err_msg = format!(
                        "project \"{}\" decode message content {} failed, {:?}",
                        self.name(),
                        hex::encode(&dec_bin_unpadding[20..msg_len]),
                        e
                    );
                    error!("{}", err_msg);
                    String::default()
                }
            }
        } else {
            String::default()
        };

        debug!(
            "project \"{}\" decode message from receiveid={} content {}",
            self.name(),
            receiveid,
            msg_content
        );
        Ok(message::WxWorkMessageDec {
            content: msg_content,
            receiveid,
        })
    }

    pub fn encrypt_msg_raw(&self, input: &[u8], random_str: &str) -> Result<Vec<u8>, String> {
        // rand_msg=AES_Decrypt(aes_msg)
        // 去掉rand_msg头部的16个随机字节和4个字节的msg_len，截取msg_len长度的部分即为msg，剩下的为尾部的receiveid
        // 网络字节序,回包的receiveid直接为空即可

        let mut input_len_buf = [0; 4];
        BigEndian::write_u32(&mut input_len_buf, input.len() as u32);

        let mut padded_plaintext: Vec<u8> = Vec::with_capacity(64 + input.len());
        padded_plaintext.extend_from_slice(random_str.as_bytes());
        padded_plaintext.extend_from_slice(&input_len_buf);
        padded_plaintext.extend_from_slice(input);

        let padded_input = self.pkcs7_encode(&padded_plaintext);
        // let block_size: usize;

        let encrypter = match self.cipher_info.lock() {
            Ok(c) => {
                let ci = &*c;
                match Aes128CbcEncoder::new_from_slices(&ci.key, &ci.iv) {
                    Ok(x) => x,
                    Err(e) => {
                        let ret = format!(
                            "project \"{}\" try to create aes256 encrypter failed, {:?}",
                            self.name(),
                            e
                        );
                        error!("{}", ret);
                        return Err(ret);
                    }
                }
            }
            Err(e) => {
                let ret = format!(
                    "project \"{}\" try to lock cipher_info failed, {:?}",
                    self.name(),
                    e
                );
                error!("{}", ret);
                return Err(ret);
            }
        };

        let mut buf = vec![0u8; padded_input.len()];
        buf.copy_from_slice(&padded_input);
        match encrypter.encrypt_padded_mut::<NoPadding>(&mut buf, padded_input.len()) {
            Ok(x) => Ok(x.to_vec()),
            Err(_) => Err(format!("project \"{}\" encrypt failed", self.name())),
        }
    }

    pub fn encrypt_msg_raw_base64(&self, input: &[u8]) -> Result<String, String> {
        // msg_encrypt = Base64_Encode(AES_Encrypt(rand_msg))
        let random_str = self.alloc_random_str();
        match self.encrypt_msg_raw(input, &random_str) {
            Ok(x) => match base64::STANDARD.encode(&x) {
                Ok(v) => {
                    debug!(
                        "project \"{}\" use random string {} and encrypt \"{}\" to {}",
                        self.name(),
                        random_str,
                        match String::from_utf8(input.to_vec()) {
                            Ok(y) => y,
                            Err(_) => hex::encode(input),
                        },
                        v
                    );
                    Ok(v)
                }
                Err(e) => {
                    let ret = format!(
                        "project \"{}\" encrypt {} and encode to base64 failed, \n{:?}",
                        self.name(),
                        hex::encode(input),
                        e
                    );
                    debug!("{}", ret);
                    Err(ret)
                }
            },
            Err(e) => Err(e),
        }
    }

    pub fn make_msg_signature(&self, timestamp: &str, nonce: &str, msg_encrypt: &str) -> String {
        // GET http://api.3dept.com/?msg_signature=ASDFQWEXZCVAQFASDFASDFSS&timestamp=13500001234&nonce=123412323&echostr=ENCRYPT_STR
        // dev_msg_signature=sha1(sort(token、timestamp、nonce、msg_encrypt))
        // sort的含义是将参数值按照字母字典排序，然后从小到大拼接成一个字符串
        // sha1处理结果要编码为可见字符，编码的方式是把每字节散列值打印为%02x（即16进制，C printf语法）格式，全部小写
        let mut datas = [self.token.as_str(), timestamp, nonce, msg_encrypt];
        datas.sort_unstable();
        let cat_str = datas.concat();

        let hash_res =
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, cat_str.as_bytes());
        // let hash_res = hash::hash(hash::MessageDigest::sha1(), cat_str.as_bytes());
        // match hash_res {
        //     Ok(x) => hex::encode(x.as_ref()),
        //     Err(e) => format!("Sha1 for {} failed, {:?}", cat_str, e),
        // }
        hex::encode(hash_res.as_ref())
    }

    pub fn check_msg_signature(
        &self,
        excepted_signature: &str,
        timestamp: &str,
        nonce: &str,
        msg_encrypt: &str,
    ) -> bool {
        let real_signature = self.make_msg_signature(timestamp, nonce, msg_encrypt);
        debug!("project \"{}\" try to check msg signature: excepted_signature={}, timestamp={}, nonce={}, msg_encrypt={}, real_signature={}", self.name(), excepted_signature, timestamp, nonce, msg_encrypt, real_signature);
        if real_signature.as_str() == excepted_signature {
            true
        } else {
            error!(
                "project \"{}\" check signature failed, except {}, reas is {}",
                self.name(),
                excepted_signature,
                real_signature
            );
            false
        }
    }

    fn alloc_nonce(&self) -> String {
        let ret = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf, ret as u64);
        hex::encode(buf)
    }

    fn alloc_random_str(&self) -> String {
        use ring::rand::SystemRandom;
        let rng = SystemRandom::new();
        let mut buf = [0; 8];
        let _ = rng.fill(&mut buf);
        hex::encode(buf)
    }

    pub fn make_xml_response(&self, msg_text: String) -> HttpResponse {
        debug!(
            "project \"{}\" start to encrypt message to base64\n{}",
            self.name(),
            msg_text
        );
        let msg_encrypt = match self.encrypt_msg_raw_base64(msg_text.as_bytes()) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "project \"{}\" encrypt_msg_raw_base64 {} failed: {}",
                    self.name(),
                    msg_text,
                    e
                );

                return HttpResponse::Forbidden()
                    .content_type("application/xml")
                    .body(message::get_robot_response_access_deny_content(e.as_str()));
            }
        };

        let nonce = self.alloc_nonce();
        let timestamp = if let Ok(x) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            x.as_secs().to_string()
        } else {
            String::from("0")
        };
        let msg_signature =
            self.make_msg_signature(timestamp.as_str(), nonce.as_str(), msg_encrypt.as_str());

        match message::pack_message_response(msg_encrypt, msg_signature, timestamp, nonce) {
            Ok(x) => HttpResponse::Ok().content_type("application/xml").body(x),
            Err(e) => {
                error!(
                    "project \"{}\" make_xml_response failed: {}",
                    self.name(),
                    e
                );

                HttpResponse::Forbidden()
                    .content_type("application/xml")
                    .body(message::get_robot_response_access_deny(e))
            }
        }
    }

    pub fn make_text_response(&self, msg: message::WxWorkMessageTextRsp) -> HttpResponse {
        let rsp_xml = match message::pack_text_message(msg) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "project \"{}\" make_text_response failed: {}",
                    self.name(),
                    e
                );

                return self.make_xml_response(e);
            }
        };

        self.make_xml_response(rsp_xml)
    }

    pub fn make_markdown_response(&self, msg: message::WxWorkMessageMarkdownRsp) -> HttpResponse {
        let rsp_xml = match message::pack_markdown_message(msg) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "project \"{}\" make_markdown_response failed: {}",
                    self.name(),
                    e
                );

                return self.make_xml_response(e);
            }
        };

        self.make_xml_response(rsp_xml)
    }

    pub fn make_error_response(&self, msg: String) -> HttpResponse {
        self.make_markdown_response(message::WxWorkMessageMarkdownRsp { content: msg })
    }

    pub fn make_markdown_response_with_text(&self, msg: String) -> HttpResponse {
        self.make_markdown_response(message::WxWorkMessageMarkdownRsp { content: msg })
    }

    pub fn make_image_response(&self, msg: message::WxWorkMessageImageRsp) -> HttpResponse {
        let rsp_xml = match message::pack_image_message(msg) {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "project \"{}\" make_image_response failed: {}",
                    self.name(),
                    e
                );

                return self.make_xml_response(e);
            }
        };

        self.make_xml_response(rsp_xml)
    }
}
