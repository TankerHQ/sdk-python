Changelog
=========

1.10
-----

Enhanced simple encryption APIs
+++++++++++++++++++++++++++++++

The encryption APIs has been extended to support the encryption and decryption of
resources of arbitrary size (previously limited to < 5MB).

New internal encryption formats
++++++++++++++++++++++++++++++++

New encryption formats are used internally in order to:

* encrypt small resources in a more compact format (lowering the overhead from 41 to 17 bytes)
* encrypt bigger resources "as a whole" without resorting to chunk encryption

The introduction of these new formats is not a breaking change per se, as data encrypted with previous SDK versions (using older internal formats) are still decryptable with this SDK version.

However, data encrypted with the Tanker SDK 1.10+ can't be decrypted with SDK versions older than 1.10.

As a recap, here is the compatibility table for your encrypted data:

 ===================   ==========================   ===========================
 Data encrypted with   Decrypting with SDK < 1.10   Decrypting with SDK >= 1.10
 ===================   ==========================   ===========================
 SDK < 1.10                 ✓                           ✓
 SDK >= 1.10                ✗                           ✓
 ===================   ==========================   ===========================


1.9
---

First public release
