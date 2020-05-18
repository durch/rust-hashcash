use hashcash::{Stamp, check};

fn main() {
    let stamp = Stamp::default();
    println!("{}", stamp.to_string());
    println!("{:?}", check(&stamp.to_string()));
}