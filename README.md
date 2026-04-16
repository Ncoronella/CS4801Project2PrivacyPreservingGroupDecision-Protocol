# CS4801Project2PrivacyPreservingGroupDecision-Protocol

An implementation of a Group Privacy Voting Protocol


Requirements

zksk -> unfortunately relies on bplip which is broken for modern python requirements  
https://github.com/spring-epfl/zksk/issues/14
There is a fixed fork of bplip at https://github.com/caro3801/bplib/tree/fix/OpenSSL
So pip install git+https://github.com/caro3801/bplib.git@fix/OpenSSL can be used then pip install zksk
