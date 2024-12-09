cargo test -p tests
cd program/
cargo prove build --docker --tag v3.3.0
cd ..
