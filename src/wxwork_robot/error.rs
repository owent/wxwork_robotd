use super::base64;

#[derive(Debug)]
pub enum Error {
    StringErr(String),
    ActixWebErr(actix_web::Error),
    Base64Err(base64::DecodeError),
    CryptoErr(block_modes::BlockModeError),
}

impl From<Error> for actix_web::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::ActixWebErr(x) => x,
            Error::StringErr(x) => actix_web::error::ErrorForbidden(x),
            Error::CryptoErr(x) => actix_web::error::ErrorForbidden(format!("{:?}", x)),
            Error::Base64Err(x) => actix_web::error::ErrorForbidden(format!("{:?}", x)),
        }
    }
}

// impl Into<actix_web::Error> for Error {
//     fn into(self) -> actix_web::Error {
//         match self {
//             Error::ActixWebErr(x) => x,
//             Error::StringErr(x) => actix_web::error::ErrorForbidden(x),
//             Error::ActixWebErr(x) => actix_web::error::ErrorForbidden(format!("{:?}", x)),
//             Error::Base64Err(x) => actix_web::error::ErrorForbidden(format!("{:?}", x)),
//         }
//     }
// }
