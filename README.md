# Command_Line_Crypter(Python version >= 3.3)
In this repo you will get a very powerfull command line encryption script.That can encrypt any text in more then 70 ways.
***
## Usage:
### Type the following commands on command line

#### Step 1: 

``` Go to the src folder of this directory, open cmd and type the following commands```

#### Step 2:For default case with --text=password --encrypt=pbkdf2_sha256

``` python crypter.py ```

#### Step 3: Enter the following command for custom text: This command will use the default encryption i.e(pbkdf2_sha256)

```python crypter.py --text=the string you want to encrypt```

#### Step 4: Enter the following command for custom text and for custom encryption

```python crypter.py --text=the string you want to encrypt --encrypt=Any encryption from the list given```

#### Step 5: You can also check the usage with the help option

```python crypter.py -h```

***
## Types of Encryptions(--encrypt argument):
|     Encryption      |   Encryption         | 
|---------------------|----------------------|
|pbkdf2_sha256        | fshp                 | 
|argon2               | ldap_bcrypt          |
|bcrypt               | ldap_bsdi_crypt      |
|bcrypt_sha256        | ldap_des_crypt       |
|cisco_asa 	          | ldap_md5             | 
|cisco_pix 	          | ldap_md5_crypt       |
|cisco_type7          | ldap_plaintext       | 
|bigcrypt 	          | ldap_salted_md5      | 
|bsdi_crypt	          | ldap_salted_sha1     |
|crypt16 	          | ldap_sha1            |
|des_crypt	          | ldap_sha1_crypt      | 
|hex_md4	          | ldap_sha256_crypt    |
|hex_md5 	          | ldap_sha512_crypt    | 
|hex_sha1 	          | apr_md5_crypt        | 
|hex_sha256           | md5_crypt            |
|hex_sha512           | plaintext            | 
|django_bcrypt        | unix_disabled        | 
|django_bcrypt_sha256 | unix_fallback        |
|django_des_crypt     | mssql2000            |
|django_disabled      | mssql2005            |
|django_pbkdf2_sha1   | mysql323             |
|django_pbkdf2_sha256 | mysql41              | 
| django_salted_md5   | oracle11             |
|django_salted_sha1   | atlassian_pbkdf2_sha1|
|cta_pbkdf2_sha1      | ldap_hex_md5   	  | 
|dlitz_pbkdf2_sha1    | ldap_hex_sha1        |
|grub_pbkdf2_sha512   | roundup_plaintext    |
|ldap_pbkdf2_sha1     | scram                |
|ldap_pbkdf2_sha256   | scrypt  			  |
|ldap_pbkdf2_sha512   | sha1_crypt           | 
|pbkdf2_sha1          | sha256_crypt         |
|pbkdf2_sha256  	  | sha512_crypt         |
|pbkdf2_sha512  	  | sun_md5_crypt        | 
|phpass               | bsd_nthash           | 
|lmhash               | nthash               |

***
## Examples:

### Default case

![default_example](https://cloud.githubusercontent.com/assets/17814101/26668813/fd4cb6d4-46c8-11e7-8255-c7af33c6f558.JPG)

### Custom text

![custom_text](https://cloud.githubusercontent.com/assets/17814101/26668814/fd4f0920-46c8-11e7-99ce-6729c30ffd02.JPG)

### Custom Text and Custom Encryption

![custom_encryption](https://cloud.githubusercontent.com/assets/17814101/26668812/fd3f0cd2-46c8-11e7-8051-fef4354ec67b.JPG)
### Help


![help](https://cloud.githubusercontent.com/assets/17814101/26668950/9545144a-46c9-11e7-883e-f2855c4bc688.JPG)