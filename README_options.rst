=============  ==============  ==============================================================================================================================
Key            Default         Description                                                                                                                   
=============  ==============  ==============================================================================================================================
address        localhost:1323  Interface and port for http server to bind to, default: localhost:1323                                                        
clientTimeout  10              Time-out for the client in seconds (e.g. when using the CLI), default: 10                                                     
fspath         ./              When file system is used as storage, this configures the path where key material and the truststore are persisted, default: ./
keysize        2048            Number of bits to use when creating new RSA keys, default: 2048                                                               
mode                           Server or client, when client it uses the HttpClient, default:                                                                
storage        fs              Storage to use, 'fs' for file system, default: fs                                                                             
=============  ==============  ==============================================================================================================================
