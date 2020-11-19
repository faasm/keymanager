# Registry &mdash; Documentation

Interface to register or pre-request a function or session for ```faasm``` with ```SGX```.  
Usually the client/developer interface.

## API

| Path | Method | Description                    |
| ------------- | ----------------------------- |----------------------------- |
| `api/v1/registry/register/<namespace>`      | ```POST```| Register a function in namespace.      |
| `api/v1/registry/pre-request/<namespace>/<function>`      |```POST```| Pre-register a  request for function in namespace.      |
| `api/v1/registry/debug/<namespace>/<function>`      |```GET```| Provides debug informations about functon.      |


### register
This interface can be used to register a new function in namespace.
To register a new function, the function has to be encrypted with ```AES```.
For the registration the corresponding CCP is required:

##### Example json-body:

```json
{	
    "name": "<Name of the function>",
    "hash": "<Hash of function-cipher>",
    "key": "<En/decryption-AES-Key>",
    "iv": "<Initialization vector>",
    "allowed-functions": ["<List of allowed function>"],
    "cfg": "<cfg>"
}
```

##### Expected output: ```None```

### prerequest
Request to transmit the de/encryption key for a payload.
This will response a ```Session ID (sid)``` which is a requirement for a request to faasm.

##### Example json-body:

```json
{
    "key": "<En/decryption-AES-Key>",
    "iv": "<Initialization vector>"
}
```

##### Expected output:

```json
{
    "sid": "<sid",
    "full-ccp": "<[list of all ccps for all functions which can be called]>"
}
```

### debug
TODO 
Provides debug information about a function like if all dependencies for chain-calls are available.
