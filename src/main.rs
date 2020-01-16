extern crate base64;
extern crate hex;

// for first challenge
// use self::base64::{encode};

use std::env;
use std::error::Error;

// for second challenge
// fn fixed_xor (s1: &String, s2: &String) -> Result<String, hex::FromHexError> {
//     let s1 = hex::decode(s1)?;
//     let s2 = hex::decode(s2)?;

//     let mut output: Vec<u8> = Vec::new();
//     let items = s1.iter().zip(s2.iter());
//     for item in items {
//         output.push(item.0 ^ item.1);
//     }

//     Ok(hex::encode(output))
// }

fn main () -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let alen = args.len();
    // First challenge:
    // for argument in &args[1..] {
    //     let data = hex::decode(argument);
    //     println!("{}", encode(&(data.unwrap())));
    // }
    //
    // second challenge:
    // if alen < 3 {
    //     println!("Need 2 arguments");
    //     return Ok(());
    // }

    // let xored_hex = fixed_xor(&args[1], &args[2])?;
    // let xored_str = hex::decode(&xored_hex)?;
    // println!("{}", xored_hex);
    // let s: String = String::from_utf8(xored_str)?;
    // println!("{}", s);

    // third challenge:
    // 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    if alen < 2 {
        println!("Need 1 argument");
        return Ok(());
    }
    let xored_str = hex::decode(&args[1])?;

    // count each character
    let mut counter = [0; 256];
    for c in &xored_str {
        counter[usize::from(*c)] += 1;
    }

    // find most used character
    let mut bigger = 0;
    let mut index: u8 = 0;
    for (i, c) in counter.iter().enumerate() {
        if bigger < *c {
            bigger = *c;
            index = i as u8;
        }
    }

    println!("e should be {}", index);
    let mut output: Vec<u8> = Vec::new();
    for c in xored_str {
        output.push(c^index);
    }
    println!("{}", String::from_utf8(output)?);

    Ok(())
}
   
