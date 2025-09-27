# hmac — Simple HOTP/TOTP generator and verifier for Go

A small, dependency-free Go library for generating and verifying one-time passwords (OTPs) using HMAC per RFC 4226 (HOTP) and RFC 6238 (TOTP). Ideal for integrating 2FA into CLIs, web services, or microservices.

- HOTP: Counter-based one-time passwords
- TOTP: Time-based one-time passwords
- otpauth:// URI generator for use with authenticator apps

Project module: `github.com/pillaimanish/hmac`  
Go version: 1.25

## Features

- Generate and verify HOTP (counter-based) OTPs
- Generate and verify TOTP (time-based) OTPs
- Build otpauth-compatible URIs to add accounts to Google Authenticator, 1Password, Authy, etc.
- Small surface area and straightforward API

## Install
