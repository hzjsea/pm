use serde_json;
use hyper;

#[derive(Debug)]
pub enum APIResponseResult {
    IDNotExists(String),
    MissPubParam(String),
    SignError(String),
    NotSpecified(String),
    KeyError(String),
    DecryptionError(String)
}

impl APIResponseResult {
    pub fn from_code(code: &str, chia_id: String) -> Self {
        match code {
            "CPE NOT EXISTS" => Self::IDNotExists(chia_id),
            "NeedPubkey" => Self::MissPubParam(chia_id),
            "CPE KEY ERROR" => Self::KeyError(chia_id),
            "DecryptionError" => Self::DecryptionError(chia_id),
            "SignError" => Self::SignError(chia_id),
            other => {
                println!("error:{}", other);
                Self::NotSpecified(chia_id)
            }
        }
    }
}

#[derive(Debug, Fail)]
pub enum PMErrors {
    #[fail(display = "CPE ID Generation Failure: {}", _0)]
    CPEIdError(String),
    #[fail(display = "Got Error While Write Key to FS: {}", _0)]
    KeyWriteError(String),
    #[fail(display = "Private/Public Key Path Error: {}", _0)]
    KeyPathError(String),
    #[fail(display = "Private/Public Key Generate Error: {}", _0)]
    KeyGenError(String),

    #[fail(display = "APIResponse Error: {:?}", _0)]
    APIResponseError(APIResponseResult),

    #[fail(display = "Private Key File Error: {}", _0)]
    PrivateKeyFileError(String),
    #[fail(display = "Public Key File Error: {}", _0)]
    PublicKeyFileError(String),

    #[fail(display = "Http Client Request Error: {}", _0)]
    HttpRequestError(String),

    #[fail(display = "Hash Error: {}", _0)]
    DownloadedHashError(String),

    #[fail(display = "Hyper return convert error:{}", _0)]
    HyperBytesError(#[cause] hyper::Error),

    #[fail(display = "deseriazation error:{}", _0)]
    DeserializeError(#[cause] serde_json::Error),

    #[fail(display = "Download Error:{}", _0)]
    DownloadGzError(#[cause] hyper::Error),

    #[fail(display = "File Error: {}", _0)]
    LocalFileWriteError(#[cause] std::io::Error)
}

impl From<serde_json::Error> for PMErrors {
    fn from(e: serde_json::Error) -> PMErrors {
        PMErrors::DeserializeError(e)
    }
}

impl From<std::io::Error> for PMErrors {
    fn from(e: std::io::Error) -> PMErrors {
        PMErrors::LocalFileWriteError(e)
    }
}
pub type Result<T> = ::std::result::Result<T, PMErrors>;