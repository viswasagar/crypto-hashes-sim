Project Abstract
This project implements a MongoDB-backed simulation of cryptographic hashing and related primitives written entirely from scratch in Python. It reproduces core building blocks used in real-world systems, including a full SHA-256 implementation, HMAC-SHA256, an AES-256 block cipher and AES-GCM style mode, toy BLAKE3-like and Argon2-like hashers, RSA key generation with PSS (SHA-256) sign/verify, Merkle tree construction and verification, and Shamir Secret Sharing over a large prime field. The code is organized for experimentation and demonstration: it generates and stores synthetic user objects and cryptographic artifacts in MongoDB, exercises share creation and reconstruction, constructs and validates Merkle proofs, signs and verifies data with RSA-PSS, computes and verifies HMACs, and measures end-to-end behavior of the simulated hashing and encryption primitives.

Key objectives

Demonstrate end-to-end interactions between hashing, authenticated encryption, public-key signatures, and distributed secret sharing inside a persisted simulation.

Provide readable, pedagogical implementations that expose internal state and algorithms for teaching, testing, and research prototypes.

Enable reproducible experiments using configurable simulation parameters and MongoDB for durable storage and queryable artifacts.

Scope and limitations

All cryptographic primitives are educational toy implementations intended for learning, not production use. Security, side-channel resistance, entropy handling, and performance optimizations are intentionally out of scope.

RSA generation and some primitives are computationally expensive in pure Python and are suitable only for small-scale simulations.

The MongoDB integration focuses on storing and retrieving simulation artifacts and does not attempt to model a production HSM, key management system, or secure enclave.

Contributions and deliverables

A single-file reference implementation demonstrating how core cryptographic components interact in a simulated environment.

Clear, modular helper functions and classes for digest, MAC, symmetric and asymmetric operations, Merkle proofs, and secret sharing that can be extended or replaced with production libraries.

Sample scripts and configuration defaults to reproduce experiments with user counts, share thresholds, and key sizes persisted in MongoDB.

This abstract summarizes an educational simulation built for teaching, experimentation, and prototyping of cryptographic workflows with persistent storage via MongoDB.
