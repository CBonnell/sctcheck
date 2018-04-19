# sctcheck

`sctcheck` is a small tool that runs checks on certificates that contain embedded SCTs.

Currently, `sctcheck` performs the following checks:

* Checks for the presence of `SignedCertifcateTimestampList` X.509 certificate extension embedded in certificates.
* If present, reads the SCTs contained in the `SignedCertificateTimestampList` and verifies that the signature in the SCTs are correct for the certificate.

Additional checks may be added in the future.

Although `sctcheck` is currently light on features, it was designed to be easy to use with minimal setup to check publicly trusted certificates. It is a Docker application, so the only requirement is that Docker be installed on the machine. Additionally, the application makes use of the known CT log list distributed in Chromium and intermediate CA list distributed by Mozilla so that the application is ready to verify SCTs out-of-the-box without having to locate the correct intermediate certificate files or manually create a known CT log list configuration file for consumption by OpenSSL.

## How to build

If you don't have Docker installed on your machine, then install that first.

Once Docker is installed, clone this repo and build the Docker image:

`
docker build . -t cbonnell/sctcheck
`

As part of the build process, Mozilla's intermediate CA CSV file will be downloaded and all intermediate certificates (encoded as PEM text within the CSV) will be written out into the image.

## How to run

The application options are specified using environment variables. Specifying values is optional; all variables have sensible defaults that are appropriate for checking publicly trusted certificates.

To check all certificate files located in `/tmp/certs`, run the following:
`docker run -v "/tmp/certs:/certs:ro" cbonnell/sctcheck`

The application will output to standard output.

The following options/environment variables are available:

| Name | Purpose | Default Value | Allowed Values | Remarks |
| --- | --- | --- | --- | --- |
| `LOG_LEVEL` | Sets the log level for the application. |`INFO` | The log level constant names of Ruby's `Logger` class (documented [here](https://ruby-doc.org/stdlib-2.1.0/libdoc/logger/rdoc/Logger.html)). | N/A |
| `CERT` | Sets the certificate file or directory of certificate files to be checked. | `/certs` | The path to an individual file containing the DER or PEM text of a certificate, or a directory containing DER and PEM text certificate files to be checked (subdirectories will be included). | For this option to work correctly, you will need to mount a volume in the Docker container so the certificate(s) can be read from the host machine. |
| `ISSUER` | Sets the issuer certificate file/directory of intermediates to be checked. | `/issuers` | The path to an individual file containing the DER or PEM text of a CA certificate, or a directory containing DER and PEM text CA certificate files (subdirectories will be included). | By default, the application will use the intermediates extracted from Mozilla's intermediates CSV file during the build process. If you wish to check certificates that have been issued by an intermediate not included in Mozilla's list, you will need to change this setting (and mount a volume containing the intermediate CA file(s)). |
| `KNOWN_LOGS` | Sets the path for the known Certificate Transparency log list. | `/usr/src/app/chrome/*.ini` | The path to a file whose format matches the format specification documented [here](https://www.openssl.org/docs/man1.1.0/crypto/CTLOG_STORE_new.html). | Chromium's known log list is embedded in the application and converted to the appropriate format during the image build process; there is generally no need to change this setting if you are checking publicly trusted certificates. |

For example, to set the `LOG_LEVEL` to `DEBUG`:
`docker run -v "/tmp/certs:/certs:ro" -e LOG_LEVEL=DEBUG cbonnell/sctcheck`

## License

`sctcheck` is licensed under the permissive MIT license.
