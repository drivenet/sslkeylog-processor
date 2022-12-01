# sslkeylog-processor
This is a tool to process logs produced by the [sslkeylog](https://github.com/drivenet/sslkeylog) utility and send them to a MongoDB instance.

## Building
`cargo build --release && upx --best target/release/sslkeylog-processor`

[UPX](https://github.com/upx/upx) is used to reduce binary size, if you prefer not using it, just skip it.

## Usage
Run the built binary to determine the command-line options.
On Windows, file names support [wildcard expansion](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.
The tool optionally supports [MaxMind geolocation database](https://www.maxmind.com/en/geoip2-databases) to store [GeoNames](https://www.geonames.org/) identifier.

## Schema
All keys are placed in the collections named `<sni>@<server_ip>:<server_port>_<year><month><day>` with the following schemas:
```javascript
// TLS pre-1.3
{
  "_id": <server_random>:BinData,
  "t": <timestamp>:DateTime,
  "r": <client_random>:BinData,
  "i": <client_ip>:int/BinData,
  "p": <client_port>:int,
  "c": <cipher_id>:int,
  "k": <premaster>:BinData,
  ["g": <geoname_id>:int],
}

// TLS 1.3:
{
  "_id": <server_random>:BinData,
  "t": <timestamp>:DateTime,
  "r": <client_random>:BinData,
  "i": <client_ip>:int/BinData,
  "p": <client_port>:int,
  "c": <cipher_id>:int,
  "h": <server_handshake>:BinData,
  "f": <client_handshake>:BinData,
  "z": <server_0>:BinData,
  "s": <client_0>:BinData,
  ["g": <geoname_id>:int],
}
```

Each collection has the following indexes:
1. `random` on the `r` field
2. `timestamp` on the `t` field
