# sslkeylog-processor
This is a tool to process logs produced by the [sslkeylog](https://github.com/drivenet/sslkeylog) utiliy and send them to a MongoDB instance.

## Building
`cargo build --release && strip target/release/sslkeylog-processor && upx --best target/release/sslkeylog-processor`

[UPX](https://github.com/upx/upx) is used to reduce binary size, if you prefer not using it, just skip it.

# Usage
Run the built binary to determine the command-line options.
On Windows, file names support [globbing](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.

# Schema
All keys are placed in the `keys` collection with the following schema:
```javascript
{
  _id: {
    "r": <server_random>:BinData,
    "i": <server_ip>:int/BinData,
    "p": <server_port>:int,
  },
  "t": <timestamp>:DateTime,
  "h": <sni>:string,
  "r": <client_random>:BinData,
  "i": <client_ip>:int/BinData,
  "p": <client_port>:int,
  "c": <cipher_id>:int,
  "p": <premaster>:BinData,
}
```
