/*!

  @mainpage Arm® CryptoCell-713™ Runtime Integration tests API overview

  This documentation contains a set of APIs that you require to test the integration
  of the Runtime software.

  The documentation is automatically generated from the source code using Doxygen.

  For more information on Doxygen, see
    http://www.doxygen.nl/

  The <i>Modules</i> section introduces the high-level module concepts that are used
  throughout this documentation.

  @section conf_status Confidentiality status

    \htmlonly
      <p overflow="hidden">
          <embed src="conf_status.html" type='text/html' width="80%" height="50px">
      </p>
    \endhtmlonly

  @section proprietary_notice Proprietary notice

    \htmlonly
      <p overflow="hidden">
          <embed type='text/html' src="proprietary_notice.html" width="80%" height="700px">
      </p>
    \endhtmlonly

 @section add_read Additional reading

    The Software Developer Manual contains information that is specific to this product. See the following documents
    for other relevant information:
    \htmlonly
    <table class="bordered">
      <caption align="left">Arm publications</caption>
      <tr>
        <th>Document name</th>
        <th>Document ID</th>
        <th>Licensee only Y/N</th>
      </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> AMBA® AXI and ACE Protocol Specification</cite>, February 2013 </td>
            <td>IHI 0022F</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> Trusted Base System Architecture V1: System Software on Arm</cite></td>
            <td>DEN 0007C</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> Power State Coordination Interface Platform Design Document</cite> </td>
            <td>DEN 0022D</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> AMBA®3 APB Protocol Specification</cite>, April 2010</td>
            <td>IHI 0024C</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> AMBA® Low Power Interface Specification</cite>, September 2016</td>
            <td>IHI 0068C</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> Trusted Boot Board Requirements: System Software on Arm</cite></td>
            <td>DEN 0006C-1</td>
            <td>N</td>
        </tr>
        <tr>
            <td><cite>Arm® <span class="keyword">CryptoCell™-713</span> Technical Reference Manual</cite></td>
            <td>Arm 101352</td>
            <td>Y</td>
        </tr>
        <tr>
            <td><cite>Arm® <span class="keyword">CryptoCell™-713</span> Configuration and Integration Manual</cite> </td>
            <td>Arm 101353</td>
            <td>Y</td>
        </tr>


        <tr>
            <td><cite>Arm® <span class="keyword">CryptoCell™-713</span> Software Integrators Manual</cite></td>
            <td>Arm 101509</td>
            <td>Y</td>
        </tr>
        <tr>
            <td><cite>Arm® <span class="keyword">CryptoCell™-713</span> Software Release Notes</cite></td>
            <td>PJDOC-1779577084-12531</td>
            <td>Y</td>
        </tr>
        <tr>
            <td><cite><span class="keyword">Arm®</span> TRNG Characterization Application Note</cite> </td>
            <td>Arm 100685</td>
            <td>Y</td>
        </tr>
    </table>
    <table class="bordered">
           <caption align="left">Other publications</caption>
        <tr>
            <th>Document name</th>
            <th>Document ID</th>
        </tr>
           <tr>
            <td>AIB20</td>
            <td>Functionality classes and evaluation methodology for deterministic random number generators</td>
        </tr>
        <tr>
            <td>ANSI X3.92-1981 </td>
            <td>Data Encryption Algorithm</td>
        </tr>
        <tr>
            <td>ANSI X3.106-1983 </td>
            <td>Data Encryption Algorithm – Modes of Operation</td>
        </tr>
        <tr>
            <td>ANSI X9.42-2003</td>
            <td>Public Key Cryptography for the Financial Services Industry: Agreement of Symmetric Keys Using Discrete Logarithm Cryptography</td>
        </tr>
        <tr>
            <td>-</td>
            <td>ChinaDRM Compliance Rules and Robustness Rules, December 2016</td>
        </tr>
        <tr>
            <td>-</td>
            <td>ChinaDRM lab: A description of ChinaDRM implementation (2016)</td>
        </tr>
        <tr>
            <td>ANSI X9.52-1998 </td>
            <td>Triple Data Encryption Algorithm Modes of Operation</td>
        </tr>
        <tr>
            <td>ANSI X9.62-2005</td>
            <td>Public Key Cryptography for the Financial Services Industry, The Elliptic Curve Digital Signature Algorithm (ECDSA)</td>
        </tr>
        <tr>
            <td>ANSI X9.63-2011</td>
            <td>Public Key Cryptography for the Financial Services Industry – Key Agreement and Key Transport Using Elliptic Curve Cryptography</td>
        </tr>
        <tr>
            <td>BSI AIS-31 </td>
            <td>Functionality Classes and Evaluation Methodology for True Random Number Generators</td>
        </tr>
        <tr>
            <td>FIPS Publication 140IG </td>
            <td>Implementation Guidance for FIPS PUB 140-2 and the Cryptographic Module Validation Program (November 2015)</td>
        </tr>
        <tr>
            <td>FIPS Publication 140-2 </td>
            <td>Security Requirements for Cryptographic Modules</td>
        </tr>
        <tr>
            <td>FIPS Publication 180-4 </td>
            <td>Secure Hash Standard (SHS)</td>
        </tr>
        <tr>
            <td>FIPS Publication 186-4 </td>
            <td>Digital Signature Standard (DSS)</td>
        </tr>
        <tr>
            <td>FIPS Publication 197 </td>
            <td>Advanced Encryption Standard</td>
        </tr>
        <tr>
            <td>FIPS Publication 198-1</td>
            <td> The Keyed-Hash Message Authentication Code (HMAC)</td>
        </tr>
        <tr>
            <td>GM/T 0005-2012</td>
            <td> Randomness Test Specification</td>
        </tr>
        <tr>
            <td>GM/T 0009-2012 </td>
            <td>SM2 Cryptography Algorithm Application Specification</td>
        </tr>
        <tr>
            <td>GM/T 0010-2012 </td>
            <td>SM2 Cryptography Message Syntax Specification</td>
        </tr>
        <tr>
            <td>GY/T 277—2014 </td>
            <td>Technical specification of digital rights management for internet television (May 2014)</td>
        </tr>
        <tr>
            <td>ISO/IEC 9797-1 </td>
            <td>Message Authentication Codes (MACs) -- Part 1: Mechanisms using a block cipher</td>
        </tr>
        <tr>
            <td>ISO/IEC 18033-2:2006</td>
            <td> Information technology -- Security techniques -- Encryption algorithms -- Part 2: Asymmetric ciphers</td>
        </tr>
        <tr>
            <td>IEEE 1363-2000 </td>
            <td>IEEE Standard for Standard Specifications for Public-Key Cryptography</td>
        </tr>
        <tr>
            <td>NIST SP 800-22 </td>
            <td>A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</td>
        </tr>
        <tr>
            <td>NIST SP 800-38A </td>
            <td>Recommendation for Block Cipher Modes of Operation: Methods and Techniques</td>
        </tr>
        <tr>
            <td>NIST SP 800-38A Addendum </td>
            <td>Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode</td>
        </tr>
        <tr>
            <td>NIST SP 800-38B </td>
            <td>Recommendation for Block Cipher Modes of Operation: the CMAC Mode for Authentication</td>
        </tr>
        <tr>
            <td>NIST SP 800-38C </td>
            <td>Recommendation for Block Cipher Modes of Operation: the CCM Mode for Authentication and Confidentiality</td>
        </tr>
        <tr>
            <td>NIST SP 800-38D </td>
            <td>Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</td>
        </tr>
        <tr>
            <td>NIST SP 800-38E </td>
            <td>Recommendation for Block Cipher Modes of Operation: the XTSAES Mode for Confidentiality on Storage Devices</td>
        </tr>
        <tr>
            <td>NIST SP 800-38F </td>
            <td>Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping</td>
        </tr>
        <tr>
            <td>NIST SP 800-56A</td>
            <td>Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography Rev. 2</td>
        </tr>
        <tr>
            <td>NIST SP 800-56B </td>
            <td>Recommendation for Pair-Wise KeyEstablishment Schemes Using Integer Factorization Cryptography</td>
        </tr>
        <tr>
            <td>NIST SP 800-57A </td>
            <td>Recommendation for Key Management – Part 1: General Rev. 4</td>
        </tr>
        <tr>
            <td>NIST SP 800-67 </td>
            <td>Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher Rev. 1</td>
        </tr>
        <tr>
            <td>NIST SP 800-90A </td>
            <td>Recommendation for Random Number Generation Using Deterministic Random Bit Generators – App C.</td>
        </tr>
        <tr>
            <td>NIST SP 800-90B </td>
            <td>Recommendation for the Entropy Sources Used for Random Bit Generation</td>
        </tr>
        <tr>
            <td>NIST SP 800-90C </td>
            <td>Recommendation for Random Bit Generator (RBG) Constructions</td>
        </tr>
        <tr>
            <td>NIST SP 800-108 </td>
            <td>Recommendation for Key Derivation Using Pseudorandom Functions</td>
        </tr>
        <tr>
            <td>NIST SP 800-135 </td>
            <td>Recommendation for Existing Application-Specific Key Derivation Functions Rev. 1</td>
        </tr>
        <tr>
            <td>PKCS #1 v1.5</td>
            <td> Public-Key Cryptography Standards RSA Encryption</td>
        </tr>
        <tr>
            <td>PKCS #1 v2.1</td>
            <td> Public-Key Cryptography Standards RSA Cryptography Specifications</td>
        </tr>
        <tr>
            <td>PKCS #3 </td>
            <td>Public-Key Cryptography Standards Diffie Hellman Key Agreement Standard</td>
        </tr>
        <tr>
            <td>PKCS #7 v1 </td>
            <td>Public-Key Cryptography Standards Cryptographic Message Syntax Standard</td>
        </tr>
        <tr>
            <td>RFC 2104 </td>
            <td>HMAC: Keyed-Hashing for Message Authentication</td>
        </tr>
        <tr>
            <td>RFC 3394 </td>
            <td>Advanced Encryption Standard (AES) Key Wrap Algorithm</td>
        </tr>
        <tr>
            <td>RFC 3566 </td>
            <td>The AES-XCBC-MAC-96 Algorithm and Its Use with IPsec</td>
        </tr>
        <tr>
            <td>RFC 3686</td>
            <td>Using Advanced Encryption Standard (AES) Counter Mode With IPsec Encapsulating Security Payload (ESP)</td>
        </tr>
        <tr>
            <td>RFC 4106</td>
            <td>The Use of Galois/Counter Mode (GCM) in IPsec Encapsulating Security Payload (ESP)</td>
        </tr>
        <tr>
            <td>RFC 4309 </td>
            <td>Using Advanced Encryption Standard (AES) CCM Mode with IPsec Encapsulating Security Payload (ESP)</td>
        </tr>
        <tr>
            <td>RFC 4543</td>
            <td> The Use of Galois Message Authentication Code (GMAC) in IPsec ESP and AH</td>
        </tr>
        <tr>
            <td>RFC 5280 </td>
            <td>Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile</td>
        </tr>
        <tr>
            <td>RFC 5649 </td>
            <td>AES Key Wrap with Padding Algorithm (August 2009)</td>
        </tr>
        <tr>
            <td>RFC 5869 </td>
            <td>HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</td>
        </tr>
        <tr>
            <td>RFC 7539</td>
            <td> ChaCha20 and Poly1305 for IETF Protocols</td>
        </tr>
        <tr>
            <td>SEC 2 v1</td>
            <td> Recommended Elliptic Curve Domain Parameters</td>
        </tr>
        <tr>
            <td>SEC 2 v2</td>
            <td> Recommended Elliptic Curve Domain Parameters</td>
        </tr>
        <tr>
            <td>SECG SEC1 </td>
            <td>Elliptic Curve Cryptography</td>
        </tr>
        <tr>
            <td>SM2 </td>
            <td> Public Key Cryptographic Algorithm Based on Elliptic Curves (December, 2010)</td>
        </tr>
        <tr>
            <td>SM3 </td>
            <td>Cryptographic Hash Algorithm (December 2012)</td>
        </tr>
        <tr>
            <td>SM4</td>
            <td> Security of the SMS4 Block Cipher Against Differential Cryptanalysis</td>
        </tr>
        <tr>
            <td>JESD223C </td>
            <td>Universal Flash Storage Host Controller Interface (UFSHCI), Version 2.1</td>
        </tr>


    </table>



    \endhtmlonly

    @section glossary Glossary

    The Arm Glossary is a list of terms used in Arm documentation, together with definitions for those terms. The Arm Glossary does not contain terms that are industry standard unless the Arm meaning differs from the generally accepted meaning.

    See https://developer.arm.com/glossary for more information.

    \htmlonly
    <table class="bordered">
      <caption align="left">Terminology</caption>
        <tr>
            <td>CCI</td>
            <td>Cache Coherent Interconnect</td>
        </tr>
        <tr>
            <td>CPP</td>
            <td>Content Protection Policy.</td>
        </tr>
        <tr>
            <td>Developer</td>
            <td>The entity that enables debug permissions.</td>
        </tr>
        <tr>
            <td>Enabler</td>
            <td>The end-user entity.</td>
        </tr>
        <tr>
            <td>HAL</td>
            <td>Hardware Abstraction Layer</td>
        </tr>
        <tr>
            <td>Host</td>
            <td>SoC processor</td>
        </tr>
        <tr>
            <td>ICV</td>
            <td>Integrated Chip Vendor</td>
        </tr>
        <tr>
            <td>IRR</td>
            <td>Interrupt Register</td>
        </tr>
        <tr>
            <td>ISR</td>
            <td>Interrupt Service Routine </td>
        </tr>
        <tr>
            <td>NVM</td>
            <td>Non-Volatile Memory</td>
        </tr>
        <tr>
            <td>NVM-FSM</td>
            <td>NVM-Manager state-machine</td>
        </tr>
        <tr>
            <td>NVM-MGR</td>
            <td>NVM-Manager module</td>
        </tr>
        <tr>
            <td>OEM</td>
            <td>Original Equipment Manufacturer </td>
        </tr>
        <tr>
            <td>PAL</td>
            <td>Platform Abstraction Layer</td>
        </tr>
        <tr>
            <td>PCI</td>
            <td>Production Chip Indicator</td>
        </tr>
        <tr>
            <td>PKA</td>
            <td>Public Key Accelerator</td>
        </tr>
        <tr>
            <td>PM</td>
            <td>Power Management</td>
        </tr>
        <tr>
            <td>PMU</td>
            <td>Power Management Unit</td>
        </tr>
        <tr>
            <td>PoR</td>
            <td>Power-on Reset</td>
        </tr>
        <tr>
            <td>REE</td>
            <td>Rich Execution Environment </td>
        </tr>
        <tr>
            <td>RoT</td>
            <td>Root-of-Trust</td>
        </tr>
        <tr>
            <td>SCU</td>
            <td>Snoop Control Unit</td>
        </tr>
        <tr>
            <td>SOS</td>
            <td>Secure Operating System</td>
        </tr>
        <tr>
            <td>SWCC</td>
            <td>Software Cache Coherency</td>
        </tr>
        <tr>
            <td>HWCC</td>
            <td>Hardware Cache Coherency</td>
        </tr>
        <tr>
            <td>TCI</td>
            <td>Test Chip Indicator</td>
        </tr>
        <tr>
            <td>TEE</td>
            <td>Trusted Execution Environment</td>
        </tr>
    </table>
    \endhtmlonly

 */