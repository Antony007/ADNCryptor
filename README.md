# ADNCryptor

A simple to use wrapper for [Crypto++](https://github.com/weidai11/cryptopp). This is intened for developers who want to get started with encryption as soon as possible without going through [Crypto++](https://github.com/weidai11/cryptopp) extensive documentation.

### Features
- RSA keys creation
- String encryption using RSA keys
- AES and XOR encryption
- Other encryption methods supported by [Crypto++](https://github.com/weidai11/cryptopp) can be easily incorporated.

### Build Instructions

This project depends upon [Crypto++](https://github.com/weidai11/cryptopp). You will have to first build [Crypto++](https://github.com/weidai11/cryptopp) and link this project against it and build.

### Usage

There are two classes included in the library.
- ADNCryptor
- QADNCryptor

##### ADNCryptor
This class is used for on-demand encryption or decryption. The Encrypt() or Decrypt() functions will only return on successful encryption or decryption of the mentioned file or incase of any error.

##### QADNCryptor
This class uses Qt Signals to notify of encryption process. Useful in decryption of large files and if you want to show progress.


### Copyleft
###### Distributed under the GPLv3 license. Copyright (c) 2018, Antony Nadar.

