extern crate base64;
extern crate hex;


use std::fs;
use std::io::{BufRead, BufReader};
use std::error::Error;

fn find_most_used(v: &Vec<u8>) -> u8 {
    // count each character
    let mut counter = [0; 256];
    for c in v {
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
    return index;
}

fn xor_string(s: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    for c in s {
        output.push(*c^key);
    }
    return output;
}

fn hamming(v1: &Vec<u8>, v2: &Vec<u8>) -> u32 {
    let zv = v1.iter().zip(v2.iter());
    let mut count = 0;
    for (va1, va2) in zv {
        let mut xor = va1 ^ va2;
        while xor != 0 {
            count += (xor & 1) as u32;
            xor = xor >> 1;
        }
    }
    // println!("{}", count);
    count
}

fn main () -> Result<(), Box<dyn Error>> {
    // veerify hamming = 37
    let s1 = String::from("this is a test");
    let s2 = String::from("wokka wokka!!!");
    println!("{}", hamming(&s1.into_bytes(), &s2.into_bytes()));

    // read the file
    let filename = "6.txt";
    let file = fs::File::open(filename).unwrap();
    let reader = BufReader::new(file);

    // // Read the file line by line using the lines() iterator from std::io::BufRead.
    let mut output = "".to_owned();
    for line in reader.lines() {
        let line = line.unwrap(); // Ignore errors.
        output.push_str(&line);
    }

    let bytes = base64::decode(&output).unwrap();

    // find key size smallest hamming distance
    let mut smallest_hamming = 0xffffffff;
    let mut matched_size = 0;
    for size in 2..40 {
        let mut hd = 0;
        for i in 0..70 {
            let first = bytes[i*size..i*size+size].to_vec();
            let second = bytes[(i+1)*size..(i+1)*size+size].to_vec();
            hd += hamming(&first, &second);

        }
        let hd = hd/(size as u32)/70;
        if hd < smallest_hamming {
            smallest_hamming = hd;
            matched_size = size;
        }
    }


    let file_size = bytes.len();
    let num_blocks = file_size / (matched_size);
    // let mut chuncks: Vec<&[u8]> = Vec::new();
    println!("file size: {}", file_size);
    println!("num blocks: {}", num_blocks);
    println!("matched size: {}", matched_size);
    let mut rescheduled: Vec<Vec<u8>> = Vec::new();
    for _ in 0..matched_size {
        rescheduled.push(Vec::new());
    }
    for i in 0..num_blocks {
        println!("i: {}", i);

        if i * (matched_size) >=  file_size {
            break;
        }

        let start = i*(matched_size);
        if (i+1) * (matched_size) >=  file_size {
            break;
        }

        let end = (i+1)*(matched_size);
        println!("start: {}, end: {}", start, end);

        for (i, b) in bytes[(start)..(end)].iter().enumerate() {
            rescheduled[i].push(*b);
        }
        // chuncks.push(&bytes[(start)..(end)]);
    }
    
    let mut mutated: Vec<Vec<u8>> = Vec::new();
    for rblock in rescheduled {
        let most_used = find_most_used(&rblock);
        let key = most_used ^ 0x65;
        let xored = xor_string(&bytes.to_vec(), key);
        mutated.push(xored);
    }

    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..mutated[0].len() {
        for j in 0..mutated.len() {
            bytes.push(mutated[j][i]);
        }
    }
    println!("xored string:\n {}", String::from_utf8(bytes).unwrap());
    // let key = "Terminator X: Bring the noise".to_string().into_bytes();
    // let key_len = key.len();
    // let mut key_index = 0;
    // let mut output: Vec<u8> = Vec::new();
    // for c in bytes {
    //     let k = key[key_index%key_len];
    //     output.push(c^k);
    //     key_index += 1;
    // }

    // println!("xored string:\n {}", String::from_utf8(output).unwrap());
    Ok(())
}

   
