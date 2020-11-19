# Guard &mdash; Documentation


* Verification of the correctness of the instantiation of an ```Enclave``` by using the ```Quote```
* Binding a function to an enclave, if the ```Enclave``` can prove the loaded code with a hash. Here, the ```Enclave``` receives the key to decrypt the function
* Output of the key for decrypting the payload in a request, if the code contains a function of an assigned set of functions of a ```sid```
* Collection of function results to build a ```callstack``` to provide full callstack of execution


## API
The Guard provides an HTTP interface to communicate with ```faaslets```.  
Payload must be transferred in ```JSON```, the input and output is specified below.  
All payload will be transmitted encrypted with ```Nonce``` and ```Auth-Tag```.

| Path | Method | Description                    |
| ------------- | ----------------------------- |----------------------------- |
| `api/v1/guard/init`      | ```POST```| Verification of the correctness of the instantiation.      |
| `api/v1/guard/bind`      |```POST```| Bind a function to ```faaslet``` in the ```Enclave```.      |
| `api/v1/guard/request`      |```POST```| Requesting the ```key``` to decrypt the payload.      |
| `api/v1/guard/result`      |```POST```| Push a meta of function.      |


### init
Verification of the correctness of the instantiation of the```WAMR```-```Enclave``` by using the ```Quote```.  
The ```Enclave``` receives an ```eid``` as a result. This ```eid``` is necessary for the ```Key-Manager``` to assign a request to an ```Enclave``` and thus to use it for encrypted communication.
For later requests of the ```Enclave``` this id is therefore fundamental necessary in the payload.
Normally each payload receives the ```eid``` in plain text in HTTP-Header and encrypted in the payload to ensure the integrity of the ```eid```.

##### Expected input:
``` json
{
    "quote": "<Quote>",
    "public-key": "<Public-key of Enclave>"
}¹
```


##### Expected output*:
``` json
{
    "public-key¹": "<Public-key of Key-Manager>",
    "eid": "<eid>",
}
```
¹ This property and value/object will be transmitted in plaintext.

### bind
Bind a function to ```faaslet``` in the ```Enclave```, if the enclave can prove the loaded code with a hash.  
The ```faaslet``` indirectly receives a Bind-id (```bid```). With this bid, the ```Key-Manager``` can assign the loaded function in the faaslet.  
In addition, the associated ```ccp``` is passed to the function that is in the ```Enclave``` as execution policy.


##### Expected input:
``` json
{
    "eid": "<eid>",
    "hash": "<Hash of the encrypted and loaded function",
}
```

##### Expected output:
``` json
{
    "bid": "<bid>",
    "key": "<Encryption key for function>",
    "ccp": "<ccp of loaded function>"
}
```

### request
Requesting the ```key``` to decrypt the payload in a request if the code is a function of an assigned set of functions of a previously initiated session referenced by the ```sid```.

##### Expected input:
``` json
{
    "bid": "<bid>",
    "sid": "<sid>",
}
```

##### Expected output:
``` json
{
    "key": "<Key to decrypt payload for request>"
}
```

### result
When a function is finished with the calculation, the ```callstack``` of chained functions is transferred to the ```Key-Manager```, with which the execution can be checked later.

##### Expected input:
``` json
{
    "bid": "<bid>",
    "callstack": "<callstack>",
    "info": "<Infos of execution>"
}
```

##### Expected output: ```None```  
