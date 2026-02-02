# sslkeylog-processor
This is a tool to process logs produced by the [sslkeylog](https://github.com/drivenet/sslkeylog) utility and send them to a MongoDB instance.

## Building
`cargo build --release`

If your build system's glibc is different from the target one, you may encounter the following error:
```text
sslkeylog-processor: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_...' not found (required by sslkeylog-processor)
```

To fix this you might want to build a [MUSL](https://musl.libc.org/)-based static binary. Prepare the environment with the following commands:
```shell
sudo apt install musl-tools
rustup target add x86_64-unknown-linux-musl
```
Then just use:
`cargo build --release --target x86_64-unknown-linux-musl`

## Usage
Run the built binary to determine the command-line options.
On Windows, file names support [wildcard expansion](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.

## Schema
All keys are placed in the collections named `<sni>@<server_ip>:<server_port>_<year><month><day>` with the following schemas:
```javascript
// TLS pre-1.3
{
  "_id": <server_random>:BinData,
  "t": <timestamp>:DateTime,
  "r": <client_random>:BinData,
  "i": <client_ip>:int/BinData,
  "k": <premaster>:BinData,
}

// TLS 1.3:
{
  "_id": <server_random>:BinData,
  "t": <timestamp>:DateTime,
  "r": <client_random>:BinData,
  "i": <client_ip>:int/BinData,
  "h": <server_handshake>:BinData,
  "f": <client_handshake>:BinData,
  "z": <server_0>:BinData,
  "s": <client_0>:BinData,
}
```

Each collection has the following indexes:
1. `random` on the `r` field (ascending)
2. `timestamp` on the `t` field (ascending)
