# Key-Manager for [Faasm](https://github.com/faasm/faasm)

Credits for this work to to [@golsch](https://github.com/golsch), who implemented this as part of his Master's thesis.

The ```Key-Manager``` is made up of two units:
* [```Registry```](./docs/registry.md)
* [```Guard```](./docs/guard.md)

FOR HW-Mode, key(key.key) and cert(cert.crt) for IAS are needed.

## Requirements
- Install dependencies: `pip3 install -r requirements.txt`
- up and running MongoDB as backend

## Tests
Requirements: gtest, libcurl

Build tests:
```
cmake tests
make -C tests
```

Run tests by executing

```
./tests/run

```
