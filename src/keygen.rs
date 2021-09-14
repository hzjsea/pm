//!
//! ### 生成设备序列号
//! 
//! 格式: CPE-XXXXXXXX
//! 
//! 该序列号禁止通过文件进行存储，必须是程序算法内部生成。  
//! md5(系统的第一块网卡的序列号+00Bw1pH3pt9YYEHIlYVSv6JHhpN0ui7l) 取中间8位，
//! go 和 rust 的实现得到的序列号必须一致。如： 
//! substr(md5(80:e6:50:00:48:8200Bw1pH3pt9YYEHIlYVSv6JHhpN0ui7l), 28, 8) ）
//! 
//! 
use mac_address::mac_address_by_name;
use crypto::md5::Md5;
use crypto::digest::Digest;
use crate::errors::{
        PMErrors,
        Result,
        APIResponseResult
};
use openssl::rsa::Rsa;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, prelude::*};
use log::{info, error, debug};
use crate::api_structures::{
    PMCheckRequest,
    PMCheckResponse,
    ChiaPid,
    ChiaState
};
use tokio::process::Command;
use std::process::Stdio;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use crate::router_info;

#[derive(Debug, Clone)]
pub struct CPEConfidentials {
    pub private_key: Vec<u8>,
    pub private_key_string: String,
    pub public_key: String,
    pub mac_addr: Vec<u8>,
    pub machine_id: String
}

impl Default for CPEConfidentials {
    fn default() -> Self {
        Self {
            private_key: Vec::default(),
            mac_addr: Vec::default(),
            machine_id: String::default(),
            public_key: String::default(),
            private_key_string: String::default()
        }
    }
}

pub async fn get_script_version(script_executable: &PathBuf) -> String {
    //let exec = format!("'{} version'", script_executable.to_str().unwrap());
    //info!("exec = {}", exec);
    match Command::new("bash")
        .arg(script_executable)
        .arg("version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await {
            Ok(p) => {
                if p.status.success() {
                    let ret = format!("{}", String::from_utf8_lossy(&p.stdout));
                    format!("{}", ret.trim())
                } else {
                    let ret = format!("{}", String::from_utf8_lossy(&p.stderr));
                    info!("return = {}", ret);
                    String::default()
                }
            }
            Err(e) => {
                error!("Script executation error:{}", e);
                 String::default()
            }
        }
}


pub async fn collect_data(
    script_executable: &PathBuf
) -> String {
    info!("parent dir of script: {:?}", script_executable.parent().unwrap());
    match Command::new("bash")
        .arg(script_executable)
        .arg("info")
        .current_dir(script_executable.parent().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await {
            Ok(p) => {
                if p.status.success() {
                    let ret = format!("{}", String::from_utf8_lossy(&p.stdout));
                    format!("{}", ret.trim())
                } else {
                    let ret = format!("{}", String::from_utf8_lossy(&p.stderr));
                    info!("return = {}", ret);
                    String::default()
                }
            }
            Err(e) => {
                format!("Script executation error:{}", e);
                 String::default()
            }
        }
}

pub async fn check_harddisk(
    script_executable: &PathBuf,
) -> String {
    match Command::new("bash")
        .arg(script_executable)
        .arg("disk")
        .current_dir(script_executable.parent().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await {
        Ok(p) => {
            if p.status.success() {
                let ret = format!("{}", String::from_utf8_lossy(&p.stdout));
                format!("{}", ret.trim())
            } else {
                let ret = format!("{}", String::from_utf8_lossy(&p.stderr));
                info!("return = {}", ret);
                String::default()
            }
        }
        Err(e) => {
            format!("Script executation error:{}", e);
                String::default()
        }
    }
}

pub async fn mount_disk(script_executable: &PathBuf) -> String {
    match Command::new("bash")
        .arg(script_executable)
        .arg("mount 4.00TB")
        .current_dir(script_executable.parent().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await {
        Ok(p) => {
            if p.status.success() {
                let ret = format!("{}", String::from_utf8_lossy(&p.stdout));
                format!("{}", ret.trim())
            } else {
                let ret = format!("{}", String::from_utf8_lossy(&p.stderr));
                info!("return = {}", ret);
                String::default()
            }
        }
        Err(e) => {
            format!("Script executation error:{}", e);
                String::default()
        }
    }
}

pub async fn upload_info(
    info: &str,
    machine_id: &str,
    uri: &str
) {
    let info_value = match serde_json::from_str::<serde_json::Value>(info) {
        Ok(mut s) => {
            info!("machine id = {}", machine_id);
            s["machine_id"] = serde_json::Value::String(format!("{}", machine_id));
            s
        }
        Err(_e) => {
            serde_json::json!({
                "machine_id": machine_id,
                "error": info
            })
        }
    };
    let s = serde_json::to_string(&info_value).unwrap();
    info!("posted content: {}", s);
    let resp = reqwest::Client::new()
        .post(uri)
        .body(s)
        .header("Content-Type", "application/json")
        .timeout(
            std::time::Duration::from_millis(850)
        )
        .send()
        .await
        .map_err(|e| PMErrors::HttpRequestError(format!("{}",e)) );
    
}


pub fn get_chia_state() -> ChiaState {
    #[cfg(target_os = "linux")]
    let state_file_path = "/temp/chia/.updating";
    #[cfg(target_os = "macos")]
    let state_file_path = "./.updating";
    let state = if std::path::Path::new(state_file_path).exists() {
        ChiaState::Updating
    } else {
        ChiaState::Normal
    };
    state
}

///! 
///! 
pub async fn generate_machine_id(path:&str) -> Result<CPEConfidentials> {
    let mut confidentials = CPEConfidentials::default();
    #[cfg(target_os="linux")]
    let name = match router_info::get_dev_by_prefix("").await {
        Ok(info) => info.device_name,
        Err(e) => {
            error!("Error to get route info:{}", e);
            format!("enp3s0")
        }
    };
    #[cfg(target_os="macos")]
    let name = format!("en0");
    match mac_address_by_name(&name) {
        Ok(m) => {
            if let Some(mac) = m {
                let d = mac.bytes();
                let ret = d.to_vec();
                let addr: Vec<String> = d.iter().map(|c| format!("{:x}", c) ).collect();
                let mut addr = addr.join(":");
                
                addr += "00Bw1pH3pt9YYEHIlYVSv6JHhpN0ui7l";//add postfix 

                let mut md5_encoder = Md5::new();
                md5_encoder.input_str(addr.as_str());
                let md5_result = md5_encoder.result_str();
                let md5_str = md5_result[12..12+8].to_string().to_uppercase();
                confidentials.machine_id = format!("CHIA-{}", md5_str);
                confidentials.mac_addr = ret;
            } else {
                return Err(PMErrors::CPEIdError(format!("No mac addr available!")));
            } 
    },
        Err(e) => return Err(PMErrors::CPEIdError(format!("{}", e))) 
    }
    
    match check_keys(path, true) {
        Ok((fpk, pubkey)) => {
            let fpk_char = fpk.iter().map(|b| *b as char).collect::<Vec<_>>();
            let fpk_string: String = fpk_char.into_iter().collect();
           confidentials.private_key = fpk;
           confidentials.private_key_string = fpk_string;
           confidentials.public_key = pubkey.unwrap();
        }
        Err(e) => return Err(e)
    };
    
    Ok(confidentials)
}


fn generate_keys(
    pkey_file_path: &PathBuf, 
    pubkey_file_path: &PathBuf
) -> Result<()> {
    let rsa = Rsa::generate(1024).unwrap();
    let private_key:Vec<u8> = rsa.private_key_to_pem().unwrap();
    let public_key:Vec<u8> = rsa.public_key_to_pem().unwrap();
    match write_all(pkey_file_path, private_key.as_slice()) {
        Ok(_) => {},
        Err(e) => return Err(PMErrors::KeyWriteError(format!("Private Key Write Error:{}", e)))
    };
    match write_all(pubkey_file_path, public_key.as_slice()) {
        Ok(_) => Ok(()),
        Err(e) => Err(PMErrors::KeyWriteError(format!("Public Key Write Error:{}", e)))
    }
}

pub fn check_keys(
    path: &str, 
    with_public: bool
) -> Result<(Vec<u8>, Option<String>)> {
    let private_key_path = Path::new(path).join("upwan-key");
    let public_key_path = Path::new(path).join("upwan-key.pub");
    if private_key_path
        .to_str()
        .is_none() || public_key_path
            .to_str()
            .is_none() 
    {
        return Err(PMErrors::KeyPathError(format!("Path of Private/Public Key Error!")));
    }
    if !path_exists(private_key_path.to_str().unwrap()) &&
       !path_exists(public_key_path.to_str().unwrap()) {
        match generate_keys(&private_key_path, &public_key_path) {
            Ok(_) => {
                info!("new key files were generated OK!");
            },
            Err(e) => {
                error!("Pub/Pri Key generation error: {}", e);
                return Err(PMErrors::KeyGenError(format!("{}", e)));
            }
        };
    }
    read_keys(&private_key_path, &public_key_path, with_public)
}

fn read_keys(
    private_key_path: &PathBuf, 
    public_key_path: &PathBuf,
    provide_public: bool,
) -> Result<(Vec<u8>, Option<String>)> {
    let fpk = match fs::File::open(private_key_path) {
        Ok(mut f) => {
            let mut d: Vec<u8> = Vec::new();
            f.read_to_end(&mut d).unwrap();
            d
        },
        Err(e) => {
            let s = format!("Error to read private key: {} Abort.", e);
            return Err(PMErrors::PrivateKeyFileError(s));
        }
    };
    let public_key = if provide_public {
        match fs::File::open(public_key_path) {
            Ok(mut f) => {
                let mut d: Vec<u8> = Vec::new();
                if let Ok(_) = f.read_to_end(&mut d) {
                    let pub_key_char = d.iter().map(|b| *b as char).collect::<Vec<_>>();
                    let pub_key_str:String = pub_key_char.into_iter().collect();
                    let len = pub_key_str.len();
                    if len < 64 {
                        let s = format!(
                            "Public key file len error, need regenerate key files.");
                        return Err(PMErrors::PublicKeyFileError(s));
                    }
                    Some(pub_key_str[26..len - 26].to_string().replace("\n", ""))
                } else {
                    let s = format!(
                        "Failed to read public key file to end: {} Abort.", 
                        public_key_path.to_str().unwrap()
                    );
                    return Err(PMErrors::PublicKeyFileError(s));
                }
            }
            Err(e) => {
                let s = format!("Error to read public key: {} Abort.", e);
                return Err(PMErrors::PublicKeyFileError(s));
            }
        }
    } else {
        None
    };
    Ok((fpk, public_key))
}

fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub fn write_all<P>(filename: P, data: &[u8]) -> io::Result<()> 
where P: AsRef<Path>, {

    let mut file = File::create(filename)?;
    file.write_all(data)?; 
    Ok(())
}

mod test {
   
    #[test]
    fn test_regex() {
        let re = regex::Regex::new(r"CPE Client (\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
        let ret = format!("CPE Client 1.0.1\nCPE Client 1.0.1");
        let cap = re.captures(&ret).unwrap();
        println!("get matches: {}", cap.get(1).map_or("", |m| m.as_str()));
        assert_eq!(1,2);
    }
}