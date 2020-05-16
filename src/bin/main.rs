use hashcash;

fn main() {
    println!("{}", hashcash::mint("test", 20, None, None, None, false));
    println!("{}", hashcash::check("1:20:20202716:test::W1D9sEpt:16b59b", None, None, None).unwrap());
}