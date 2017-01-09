## dcos-oauth

## Newsa

11/14/2016: Mesosphere is working on open sourcing parts of our Enterprise DC/OS IAM service, including support for OpenID Connect. This will be replacing dcos-oauth in its entirety. Looking forward to working with everyone on that as soon as it has been released. Current target is early Q1 2017.

## Installation

### Prerequisites
* Go 1.6

Once the environment is set for Go, run `make` to compile and `make install` to install.

## Tests

Running `make test` will build the docker image `authdcos` and run tests in the `test` directory.
The API integration tests will run two containers:
- `authdcos-zk`
- `authdcos-api`

then send a request with  the available HTTP methods for the API routes. Please refer to `/api/routes.go` for
more details.

## HTTP API specification
The file `docs/apispec-swagger.json` specifies the behavior bouncer's HTTP API,
using [Swagger 2.0 notation](https://github.com/swagger-api/swagger-spec).

For ease of viewing, the contents of `apispec-swagger.json` can be pasted
into the [Swagger editor](http://editor.swagger.io) — resulting in a useful
and beautiful HTML live-rendering of the API specification. Note that the
HTML output does not necessarily contain all detail specified in the JSON
file.

## License

Apache License 2.0
