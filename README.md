# sslkeylog-processor
This is an utility to process logs produced by [sslkeylog](https://github.com/drivenet/sslkeylog) and send them to MongoDB instance.

## Building
`cargo build --release`

# Usage
Run the built binary to determine the command-line options.
On Windows, file names support [globbing](https://docs.rs/glob/), on other OSes shell expansion is expected to take care of that.
