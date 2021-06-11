# sslkeylog-processor
This is a tool to process logs produced by the [sslkeylog](https://github.com/drivenet/sslkeylog) utiliy and send them to a MongoDB instance.

## Building
`cargo build --release && strip target/release/sslkeylog-processor && upx --best target/release/sslkeylog-processor`

[UPX](https://github.com/upx/upx) is used to reduce binary size, if you prefer not using it, just skip it.

# Usage
Run the built binary to determine the command-line options.
On Windows, file names support [globbing](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.

# Schema
All keys are placed in the collections named `keys_<server_ip>_<server_port>_<sni>` with the following schema:
```javascript
{
  _id: <client_random>:BinData,
  "t": <timestamp>:DateTime,
  "r": <server_random>:BinData,
  "i": <client_ip>:int/BinData,
  "p": <client_port>:int,
  "c": <cipher_id>:int,
  "k": <premaster>:BinData,
}
```
