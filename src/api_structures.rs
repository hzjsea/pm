use serde::{self, Deserialize, Serialize};
use serde_json::json;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::collections::HashMap;

const SECRET: &'static str = "CHFfxQA3tqEZgKusgwZjmI5lFsoZxXGXnQLA97oYga2M33sLwREZyy1mWCM8GIIA";

mod crypto_utils {
    use hmac::{Hmac, Mac, NewMac};
    use sha2::Sha256;
    use std::fmt::Write;
    use openssl::rsa::{Padding, Rsa};

    type Hmacsha256 = Hmac<Sha256>;
    fn encode_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            match write!(&mut s, "{:02x}", b) {
                Ok(_) => {},
                Err(_) => {}
            };
        }
        s
    }
    
    pub fn hash_hmac(secret: &str, msg: &str) -> String {
        let mut mac = Hmacsha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(msg.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        encode_hex(&code_bytes)
    }

    pub fn openssl_private_encrypt(pk:&[u8], msg: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out: [u8; 4096] = [0;4096];
        let rsa = Rsa::private_key_from_pem(pk).unwrap();
        let size = rsa.private_encrypt(msg, &mut out, Padding::PKCS1).unwrap();
        //let x = rsa.public_decrypt(msg, &mut out, Padding::PKCS1).unwrap();
        Ok(out[..size].to_vec())
    }
}

fn mark_default_false() -> bool {
    false
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChiaPid {
    pub chia_daemon: String,
    pub chia_full_node: String,
    pub chia_harvester: String,
    pub chia_farmer: String,
    pub chia_wallet: String,
    #[serde(default = "mark_default_false")]
    pub is_correct: bool
}

impl ChiaPid {
    pub fn from_string(s: String) -> Self {
        match serde_json::from_str::<Self>(&s) {
            Ok(mut s) => {
                s.is_correct = true;
                s
            },
            Err(_e) => Self::error()
        }
    }

    pub fn all_started(&self) -> bool {
        self.chia_daemon.len() > 0 &&
        self.chia_full_node.len() > 0 &&
        self.chia_harvester.len() > 0 &&
        self.chia_farmer.len() > 0 &&
        self.chia_wallet.len() > 0 &&
        self.is_correct
    }

    pub fn partial_started(&self) -> bool {
        self.is_correct && (
            self.chia_daemon.len() > 0 ||
            self.chia_full_node.len() > 0 ||
            self.chia_harvester.len() > 0 ||
            self.chia_farmer.len() > 0 ||
            self.chia_wallet.len() > 0
        )
    }

    pub fn error() -> Self {
        Self::default()
    }
}

impl Default for ChiaPid {
    fn default() -> Self {
        Self {
            chia_daemon:String::default(),
            chia_full_node: String::default(),
            chia_harvester: String::default(),
            chia_farmer: String::default(),
            chia_wallet: String::default(),
            is_correct: false
        }
    }
}

fn set_empty_string() -> String {
    String::default()
}

fn _set_empty_ssh() -> Vec<String> {
    Vec::default()
}

#[derive(Serialize, Debug, Clone)]
pub struct Versions {
    pm_version: String,
    script_version: String,
    chia_version: String
}

#[derive(Serialize, Debug, Clone)]
pub struct HarddiskUpload {
    pub machine_id: String,
    pub info: String
}

impl HarddiskUpload {
    pub fn new_stringified(
        machine_id: &str,
        info: &str
    ) -> String {
        let nonce: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let base64ed_info = openssl::base64::encode_block(info.as_bytes());
        let mut json = json!({
            "action": "disk_info",
            "machine_id": machine_id,
            "nonce": nonce,
            "info": base64ed_info
        });
        let sign = crypto_utils::hash_hmac(SECRET, &json.to_string());
        json["sign"] = json!(sign);
        json.to_string()
    }
}

pub enum ChiaState {
    Updating,
    Normal,
    Unknown
}

impl From<&str> for ChiaState {
    fn from(s: &str) -> Self {
        match s {
            "Updating" => Self::Updating,
            "Normal" => Self::Normal,
            _ => Self::Unknown
        }
    }
}

impl From<&ChiaState> for &str {
    fn from(s: &ChiaState) -> &'static str {
        match s {
            ChiaState::Unknown => "Unknown",
            ChiaState::Updating => "Updating",
            ChiaState::Normal => "Normal"
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct PMCheckRequest {
    pub action: String,
    pub machine_id: String,
    pub key: String,
    pub nonce: String,
    pub r#pub: String,
    pub r#type: String,
    pub versions: Versions,
    pub sign: String
}

impl PMCheckRequest {
    pub fn new_stringified(
        machine_id: &str, 
        priv_key: &str,
        r#type: &str,
        chia_version: &str,
        pm_version: &str,
        script_version: &str,
        r#pub: Option<&str>,
        state: &ChiaState
    ) -> String {
        let nonce: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let key = crypto_utils::openssl_private_encrypt(priv_key.as_bytes(), nonce.as_bytes()).unwrap();
        let key = openssl::base64::encode_block(key.as_slice());
        let platform = match std::env::consts::ARCH {
            "x86" | "x86_64" => "X86",
            "arm" | "aarch64" => "ARM",
            "mips" | "mips64" => "MIPS",
            _ => "NOT_SUPPORTED"
        };
        let chia_state: &str = state.into();
        let mut json = json!({
            "action": "check",
            "machine_id": machine_id,
            "state": chia_state,
            "key": key,
            "type": r#type,
            "nonce": nonce,
            "versions": json!({
                "pm_version": pm_version,
                "script_version": script_version,
                "chia_version": chia_version
            }),
            "platform": platform
        });
        if let Some(s) = r#pub {
            json["pub"] = json!(s);
        }
        let sign = crypto_utils::hash_hmac(SECRET, &json.to_string());
        json["sign"] = json!(sign);
        json.to_string()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct PMCheckApp {
    pub url: String,
    #[serde(default = "set_empty_string")]
    pub hash: String,
    #[serde(default = "set_empty_string")]
    pub executable_hash: String,
    #[serde(default = "set_empty_string")]
    pub tag: String,
    #[serde(default = "set_empty_string")]
    pub command: String
}

impl Default for PMCheckApp {
    fn default() -> PMCheckApp {
        Self {
            url: String::default(),
            tag: String::default(),
            command: String::default(),
            hash: String::default(),
            executable_hash: String::default()
        }
    }
}

fn set_empty_app() -> HashMap<String, PMCheckApp> {
    HashMap::default()
}

#[derive(Deserialize, Debug, Clone)]
pub struct PMCheckResponse {
    pub ok: bool,
    #[serde(default = "set_empty_string")]
    pub code: String,
    #[serde(default = "set_empty_string")]
    pub msg: String,
    #[serde(default = "set_empty_app")]
    pub app: HashMap<String, PMCheckApp>,
    #[serde(default = "set_empty_string")]
    pub miner_pool_address: String,
    #[serde(default = "set_empty_string")]
    pub wallet_address: String,
}

use log::{info, error};

fn _set_dropbear(switch: bool) {
    let mut conf = Vec::<String>::new();
    //let mut config_item:Option<String> = None;
    #[cfg(target_os = "linux")]
    let bear_path = "/etc/config/dropbear";
    #[cfg(target_os = "macos")]
    let bear_path = "./ssh_test/dropbear";
    if let Ok(lines) = read_lines(bear_path) {
        for line in lines {
            if let Ok(conf_item) = line {
                if !conf_item.contains("option PasswordAuth") {
                    conf.push(conf_item.to_owned());
                }
            }
        }
    }
    if switch {
        conf.push(format!("    option PasswordAuth 'on'"));
    } else {
        conf.push(format!("    option PasswordAuth 'off'"));
    }
    let to_write = conf.join("\n");
    if let Err(e) = write_all(bear_path, to_write.as_bytes()) {
        error!("write dropbear file error:{}!",e);
    };
}


pub fn _handle_ssh(_res: &PMCheckResponse, ssh_path: &str) {
    let upwan_mark = "CPE@UPWAN.NET";
    let mut orignal_ssh = Vec::<String>::new();
    let mut existed_ssh = Vec::<String>::new();
    let ssh_path2 = "/etc/dropbear/authorized_keys";
    let path = match std::fs::File::open(ssh_path) {
        Err(_) => ssh_path2,
        Ok(_) => ssh_path
    };
    
    if let Ok(lines) = read_lines(path) {
        for line in lines {
            if let Ok(ip) = line {
                orignal_ssh.push(ip.clone());
                let ip = match ip.strip_suffix(" ") {
                    Some(v) => v,
                    None => &ip
                };
                if !ip.ends_with(upwan_mark) {
                    existed_ssh.push(ip.to_owned());
                }  
            }
        }
    }

   
    let joined = existed_ssh.join("\n");
    let orignal_ssh_joined = orignal_ssh.join("\n");
    if joined == orignal_ssh_joined {
        info!("SSH no updates!");
        return;
    }
    if let Err(e) = write_all(path, joined.as_bytes()) {
        error!("write ssh file error:{}!",e);
    };

}

use std::fs::File;
use std::io::{self, BufRead,prelude::*};
use std::path::Path;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn write_all<P>(filename: P, data: &[u8]) -> io::Result<()> 
where P: AsRef<Path>, {

    let mut file = File::create(filename)?;
    file.write_all(data)?; 
    Ok(())
}