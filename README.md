# OpenPGP CSP

A CSP for the OpenPGP card.

These project should be considered in addition to the [OpenPGP minidriver project](http://www.mysmartlogon.com/products/openpgp-card-mini-driver.html).

It has been designed to provide support for the OpenPGP card and especially the possibility to request certificate from the Windows PKI.

![certificate_enrollment_demo](https://raw.githubusercontent.com/vletoux/OpenPGP-CSP/master/GitContent/openpgp_certificate.gif)

## Getting Started

Open the solution in Visual Studio and build the project.
The version used for the development is Visual Studio 2012

### Prerequisites

A code signing certificate with the kernel mode option or using the prebuilt binaries.
Indeed, at the opposite of a minidriver, a CSP MUST be signed.

### Installing

Copy the binaries to a known location. C:\windows\system32 is well known one.
Edit the .reg file at the root of the project and add the ATR of the card to test.
The OpenPGP Card v2 & v3 have already been added.
Double click on the .reg file to install.

## Running the tests

Run certutil -scinfo (beware of the 32 or 64 bits version when doing test - c:\windows\syswow64\certutil.exe is the 32 bits one)
and double check that the Card name is filled.

### Certutil test with the "Open PGP Card v2"



```
  0: SCM Microsystems Inc. SCR33x USB Smart Card Reader 0
--- Lecteur : SCM Microsystems Inc. SCR33x USB Smart Card Reader 0
--- Statut : SCARD_STATE_PRESENT | SCARD_STATE_UNPOWERED
--- Statut : Carte disponible pour utilisation.
---   Carte : OpenPGP Card v2
---    ATR :
        3b da 18 ff 81 b1 fe 75  1f 03 00 31 c5 73 c0 01   ;......u...1.s..
        40 00 90 00 0c                                     @....
```

## Authors

* **Vincent LE TOUX** - *Initial commit*

## License

This project is licensed under the LGPL License

