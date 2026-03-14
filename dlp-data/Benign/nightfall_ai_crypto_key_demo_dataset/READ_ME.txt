# Sample Dataset for Testing Cryptographic Key Detection

This sample dataset demonstrates Nightfall's ability to detect all types of cryptographic keys. The data has been fully de-identified and can be used to test PHI detection on any data loss prevention (DLP) platform.

## Background

Nightfall AI supports detection of the following types of cryptographic keys:

* RSA PRIVATE KEY
* DSA PRIVATE KEY
* EC PRIVATE KEY
* OPENSSH PRIVATE KEY
* PRIVATE KEY
* ENCRYPTED PRIVATE KEY
* PGP PRIVATE KEY

## Positive Samples

In positive samples folder, you'll find a variety sensitive cryptographic keys in a variety of lengths. 

## Negative Samples

In negative samples folder, you'll find a public key (non-sensitive) and a log snippet that may generate false positives on other DLP systems.
