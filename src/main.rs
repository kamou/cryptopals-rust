extern crate base64;
extern crate openssl;

use std::error::Error;

fn pkcs7_add_padding (data: &mut Vec<u8>, bsize: usize) {
    let padding: usize = (bsize - data.len()) % bsize;
    let mut padding = vec![padding as u8; padding];
    data.append(&mut padding);
}

fn main () -> Result<(), Box<dyn Error>> {
    let mut data = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_add_padding(&mut data, 20);

    assert_eq!(data, [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4]);
    Ok(())
}

   
