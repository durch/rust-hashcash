# rust-hashcash [docs](https://durch.github.io/rust-hashcash/hashcash/)

MIT licensed Rust implementation of the [hashcash](http://www.hashcash.org/) algorithm ported from [hashcash.py](https://www.gnosis.cx/download/gnosis/util/hashcash.py). Notable differences are that only version 1 of hashcash is supported and `sha3` is used as the default hashing algorithm. `sha1` is available with a feature flag.

## Example

```rust

use hashcash::{Stamp, check};

fn main {

    let stamp = Stamp::default();
    assert!(check(stamp.to_string()));

}

```

## Usage

```toml
[dependencies]
rust-hashcash = "0.1"
```

### With sha1

```toml
[dependencies]
rust-hashcash = {version = "0.1", features=["sha1"]}
```
