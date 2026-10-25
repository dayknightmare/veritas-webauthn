use url::Url;

#[must_use]
#[inline]
pub fn get_host(url: Url) -> String {
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port().unwrap_or(0);
    
    if port != 0 {
        format!("{}:{}", host, port)
    } else {
        host
    }   
}