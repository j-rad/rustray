use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
struct MyKx;
impl SupportedKxGroup for MyKx {}
