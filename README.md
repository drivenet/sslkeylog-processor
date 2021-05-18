# sslkeylog-processor
This is an utility to process logs produced by [sslkeylog](https://github.com/drivenet/sslkeylog) and send them to MongoDB instance.

## Building
`cargo build --release`

# Usage
Run the built binary to determine the command-line options.
On Windows, file names support [globbing](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.

# Schema
```javascript
{
  _id: {
    "c": <client_random>:BinData,
    "h": <sni>:string,
    "i": <server_ip>:int/BinData,
    "p": <server_port>:int,
  },
  "t": <timestamp>:DateTime,
  "i": <client_ip>:int/BinData,
  "p": <client_port>:int,
  "c": <cipher_id>:int,
  "r": <server_random>:BinData,
  "p": <premaster>:BinData,
}
```
