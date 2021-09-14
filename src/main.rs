//!
//! ### pm_info 功能
//!
//! 该程序为测试功能， 程序启动后直接调用脚本运行采集chia数据，采集完成之后输出
//! 采集脚本调用方法为 /root/chia/chia_script info
//! 

#[macro_use]
extern crate failure;

use clap::{App,Arg};
use log::{error, info, logger};
use std::{io::Read, path::{Path}};
mod api_structures;
mod keygen;
mod errors;


pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");


fn init_sys_log(level: &str, pid: i32) {
    use syslog::{Facility, Formatter3164, BasicLogger};
    use log::LevelFilter;
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "Chia-PM".into(),
        pid: pid,
    };
    
    let max_level = match level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "off" => LevelFilter::Off,
        "trace" => LevelFilter::Trace,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info
    };

    info!("max_level => {}",max_level);
    println!("max_level => {}",max_level);

    let logger = syslog::unix(formatter).expect("could not connect to syslog");
    match log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .map(|()| log::set_max_level(max_level)) {
                Ok(_) => println!("Syslog config done, set max level: {}!", level),
                Err(e) => {
                    println!("SetLoggerError: {}", e);
                }
            };
}

fn read_from_file_string<P>(filename: P) -> Result<String, ()>
where P: AsRef<Path> {
    match std::fs::File::open(filename) {
        Ok(mut f) => {
            let mut d = String::new();
            f.read_to_string(&mut d).unwrap();
            Ok(d)
        },
        Err(e) => {
            Err(())
        }
    }
}
fn main() {
    let version = VERSION.unwrap_or("0.1");
    let app = App::new("Chia-PM")
            .version(version)
            .author("UPYUN <gongxun.xia@upai.com>")
            .about("Process Manager")
            .subcommand(
                App::new("console")
                .about("run on console mode")
                .arg(Arg::with_name("target")
                .long("target")
                .value_name("TARGET")
                .takes_value(true)
            ))
            .arg(Arg::with_name("target")
                    .long("target")
                    .value_name("TARGET")
                    .takes_value(true));

    let is_daemonize = match app.clone().get_matches().subcommand() {
        ("console", _) => false,
        _ => true
    };
    let target_http = match app.get_matches().value_of("target") {
        Some(s) => s.to_owned(),
        None => "https://chia.houdeyun.cn/api/chia/".to_owned()
    };

    // 创建日志
    if is_daemonize {
        println!("{}",is_daemonize);
        let pid = std::process::id() as i32;
        init_sys_log("info", pid);
    } else {
        env_logger::init();
    }

    #[cfg(target_os = "macos")]
    let download_save_to = "./downloads";
    #[cfg(target_os = "linux")]
    let download_save_to = "/root/chia";

    #[cfg(target_os = "macos")]
    let key_path = "./keys";
    #[cfg(target_os = "linux")]
    let key_path = "/etc/upyun";
   


    let script_executable = Path::new(download_save_to).join("chia_script.sh");
    // 重新创建pid文件
    if is_daemonize {
        println!("Daemonize the process...");
        let pidfile = std::path::Path::new("/dev/shm").join("chia-pm.pid");
        if pidfile.exists() {
            match read_from_file_string(&pidfile) {
                Ok(s) => {
                    if let Ok(old_pid) = s.parse::<u32>() {
                       match std::process::Command::new("kill")
                                .arg("-9")
                                .arg(s)
                                .output() {
                            Ok(_) => {
                                println!("old process [{}] killed ok!", old_pid);
                            }
                            Err(e) => {
                                println!("failed to kill old process with pid: [{}]", old_pid);
                            }
                        }
                    }
                },
                Err(_) => {}
            }
            if let Err(e) = std::fs::remove_file(&pidfile) {
                error!("error to remove pid file: {}", e);
                return;
            }
        }
    }


    // entry runtime
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async{
        // let confidentials = keygen::generate_machine_id(key_path).await.unwrap();
        let mut harddisk_checker = tokio::time::interval(tokio::time::Duration::from_secs(10)); 
        let is_chia_running = true;
        loop {
            tokio::select! {
                _h = harddisk_checker.tick() => {
                    // Generate machine_id according to the network card
                    // let confid = confidentials.clone();
                    // bash /root/chia/chia_script info
                    let scri = script_executable.clone();
                    // target http://chia.holdcloud.com
                    let th = target_http.clone();
                    tokio::spawn(async move {
                        // let disk_info = keygen::check_harddisk(&scri).await;
                        // let upload = api_structures::HarddiskUpload::new_stringified(&confid.machine_id , &disk_info);
                        // if let Err(e) = reqwest::Client::new()
                        //     .post(&th)
                        //     .body(upload)
                        //     .header("Content-Type", "application/json")
                        //     .timeout(
                        //         std::time::Duration::from_millis(850)
                        //     )
                        //     .send()
                        //     .await {
                        //     error!("Upload Disk Info Error: {}", e);
                        // }
                        if is_chia_running {
                            let uri = if th.ends_with("/") {
                                format!("{}collect_info/post", th)
                            } else {
                                format!("{}/collect_info/post", th)
                            };
                            let info = keygen::collect_data(&scri).await;
                            let info_value = match serde_json::from_str::<serde_json::Value>(&info) {
                                Ok(mut s) => {
                                    info!( "{}", s  )
                                }
                                Err(_e) => {
                                }
                            };
                            // keygen::upload_info(
                            //     &stat, 
                            //     &confid.machine_id, 
                            //     &uri
                            // ).await;
                        }
                    });
            }
        }
    }
    });
   

}
