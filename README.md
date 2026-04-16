# CS4801Project2PrivacyPreservingGroupDecision-Protocol

An implementation of a Group Privacy Voting Protocol

To Run:
- pip install fastecdsa shamirs lagrange petlib
- zksk unfortunately relies on bplip which is broken for modern python requirements  
https://github.com/spring-epfl/zksk/issues/14
There is a fixed fork of bplip at https://github.com/caro3801/bplib/tree/fix/OpenSSL
So use pip install git+https://github.com/caro3801/bplib.git@fix/OpenSSL can be used then pip install zksk

Unfortunately these libraries rely on openssl, which is not available as a Windows binary.
You can use homebrew on mac to install openssl.
On a Windows machine, you can use WSL and a venv to install the packages and run.

