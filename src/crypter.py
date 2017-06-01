import argparse
import sys
from passlib.hash import pbkdf2_sha256,argon2,bcrypt, bcrypt_sha256,cisco_asa, cisco_pix, cisco_type7
from passlib.hash import bigcrypt, bsdi_crypt, crypt16, des_crypt, hex_md4, hex_md5, hex_sha1, hex_sha256, hex_sha512, htdigest
from passlib.hash import django_bcrypt, django_bcrypt_sha256, django_des_crypt, django_disabled, django_pbkdf2_sha1, django_pbkdf2_sha256, django_salted_md5, django_salted_sha1
from passlib.hash import fshp,ldap_bcrypt, ldap_bsdi_crypt, ldap_des_crypt, ldap_md5, ldap_md5_crypt, ldap_plaintext, ldap_salted_md5, ldap_salted_sha1, ldap_sha1, ldap_sha1_crypt, ldap_sha256_crypt, ldap_sha512_crypt
from passlib.hash import apr_md5_crypt, md5_crypt,plaintext, unix_disabled, unix_fallback,mssql2000, mssql2005,mysql323, mysql41,oracle10, oracle11
from passlib.hash import atlassian_pbkdf2_sha1, cta_pbkdf2_sha1, dlitz_pbkdf2_sha1, grub_pbkdf2_sha512, ldap_pbkdf2_sha1, ldap_pbkdf2_sha256, ldap_pbkdf2_sha512, pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512
from passlib.hash import phpass,postgres_md5,ldap_hex_md5, ldap_hex_sha1, roundup_plaintext,scram,scrypt,sha1_crypt,sha256_crypt, sha512_crypt,sun_md5_crypt,bsd_nthash, lmhash, msdcc, msdcc2, nthash


def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('--text', type=str, default='password', 
                            help='String you want to Encrypt')
        parser.add_argument('--encrypt', type=str, default='pbkdf2_sha256',
                            help='Which type of Encryption do you want in lower case')
        args = parser.parse_args()
        sys.stdout.write(str(Crypter(args)))

def Crypter(args):
        if args.encrypt == 'pbkdf2_sha256':
                return pbkdf2_sha256.hash(args.text)
        elif args.encrypt == 'oracle11':
                return oracle11.hash(args.text)
        elif args.encrypt == 'argon2':
                return argon2.hash(args.text)
        elif args.encrypt == 'bcrypt':
                return bcrypt.hash(args.text)
        elif args.encrypt == 'bcrypt_sha256':
                return bcrypt_sha256.hash(args.text)
        elif args.encrypt == 'cisco_asa':
                return cisco_asa.hash(args.text)
        elif args.encrypt == 'cisco_pix':
                return cisco_pix.hash(args.text)
        elif args.encrypt == 'cisco_type7':
                return cisco_type7.hash(args.text)
        elif args.encrypt == 'bigcrypt':
                return bigcrypt.hash(args.text)
        elif args.encrypt == 'bsdi_crypt':
                return bsdi_crypt.hash(args.text)
        elif args.encrypt == 'des_crypt':
                return des_crypt.hash(args.text)
        elif args.encrypt == 'hex_md4':
                return hex_md4.hash(args.text)
        elif args.encrypt == 'hex_md5':
                return hex_md5.hash(args.text)
        elif args.encrypt == 'hex_sha1':
                return hex_sha1.hash(args.text)
        elif args.encrypt == 'hex_sha256':
                return hex_sha256.hash(args.text)
        elif args.encrypt == 'hex_sha512':
                return hex_sha512.hash(args.text)
        elif args.encrypt == 'django_bcrypt':
                return django_bcrypt.hash(args.text)
        elif args.encrypt == 'django_disabled':
                return django_disabled.hash(args.text)
        elif args.encrypt == 'django_bcrypt_sha256':
                return django_bcrypt_sha256.hash(args.text)
        elif args.encrypt == 'django_des_crypt':
                return django_des_crypt.hash(args.text)
        elif args.encrypt == 'django_pbkdf2_sha1':
                return django_pbkdf2_sha1.hash(args.text)
        elif args.encrypt == 'django_pbkdf2_sha256':
                return django_pbkdf2_sha256.hash(args.text)
        elif args.encrypt == 'django_salted_md5':
                return django_salted_md5.hash(args.text)
        elif args.encrypt == 'django_salted_sha1':
                return django_salted_sha1.hash(args.text)
        elif args.encrypt == 'fshp':
                return fshp.hash(args.text)
        elif args.encrypt == 'ldap_bcrypt':
                return ldap_bcrypt.hash(args.text)
        elif args.encrypt == 'ldap_md5':
                return ldap_md5.hash(args.text)
        elif args.encrypt == 'ldap_plaintext':
        		return ldap_plaintext.hash(args.text)
        elif args.encrypt == 'ldap_sha1':
        		return ldap_sha1.hash(args.text)
        elif args.encrypt == 'ldap_bsdi_crypt':
        		return ldap_bsdi_crypt.hash(args.text)
        elif args.encrypt == 'ldap_hex_md5':
        		return ldap_hex_md5.hash(args.text)
        elif args.encrypt == 'ldap_hex_sha1':
        		return ldap_hex_sha1.hash(args.text)
        elif args.encrypt == 'ldap_md5_crypt':
        		return ldap_md5_crypt.hash(args.text)
        elif args.encrypt == 'ldap_pbkdf2_sha1':
        		return ldap_pbkdf2_sha1.hash(args.text)
        elif args.encrypt == 'ldap_pbkdf2_sha256':
        		return ldap_pbkdf2_sha256.hash(args.text)
        elif args.encrypt == 'ldap_pbkdf2_sha512':
        		return ldap_pbkdf2_sha512.hash(args.text)
        elif args.encrypt == 'ldap_salted_md5':
        		return ldap_salted_md5.hash(args.text)
        elif args.encrypt == 'ldap_salted_sha1':
        		return ldap_salted_sha1.hash(args.text)
        elif args.encrypt == 'ldap_sha1_crypt':
       		    return ldap_sha1_crypt.hash(args.text)
        elif args.encrypt == 'ldap_sha256_crypt':
        		return ldap_sha256_crypt.hash(args.text)
        elif args.encrypt == 'ldap_sha512_crypt':
        		return ldap_sha512_crypt.hash(args.text)
        elif args.encrypt == 'apr_md5_crypt':
        		return apr_md5_crypt.hash(args.text)
        elif args.encrypt == 'md5_crypt':
        		return md5_crypt.hash(args.text)
        elif args.encrypt == 'plaintext':
       		    return plaintext.hash(args.text)
        elif args.encrypt == 'unix_disabled':
        		return unix_disabled.hash(args.text)
        elif args.encrypt == 'unix_fallback':
        		return unix_fallback.hash(args.text)
        elif args.encrypt == 'mssql2000':
       		    return mssql2000.hash(args.text)
       	elif args.encrypt == 'mssql2005':
       		    return mssql2005.hash(args.text)
       	elif args.encrypt == 'mysql323':
       		    return mysql323.hash(args.text)
       	elif args.encrypt == 'mysql41':
       		    return mysql41.hash(args.text)
       	elif args.encrypt == 'atlassian_pbkdf2_sha1':
       		    return atlassian_pbkdf2_sha1.hash(args.text)
       	elif args.encrypt == 'cta_pbkdf2_sha1':
       		    return cta_pbkdf2_sha1.hash(args.text)
       	elif args.encrypt == 'dlitz_pbkdf2_sha1':
       		    return dlitz_pbkdf2_sha1.hash(args.text)
       	elif args.encrypt == 'grub_pbkdf2_sha512':
       		    return grub_pbkdf2_sha512.hash(args.text)
       	elif args.encrypt == 'pbkdf2_sha1':
       		    return pbkdf2_sha1.hash(args.text)
       	elif args.encrypt == 'pbkdf2_sha512':
       		    return pbkdf2_sha512.hash(args.text)
       	elif args.encrypt == 'phpass':
       		    return phpass.hash(args.text)
       	elif args.encrypt == 'roundup_plaintext':
       		    return roundup_plaintext.hash(args.text)
       	elif args.encrypt == 'sun_md5_crypt':
       		    return sun_md5_crypt.hash(args.text)
       	elif args.encrypt == 'scram':
       		    return scram.hash(args.text)
       	elif args.encrypt == 'scrypt':
       		    return scrypt.hash(args.text)
       	elif args.encrypt == 'sha1_crypt':
       		    return sha1_crypt.hash(args.text)
       	elif args.encrypt == 'sha256_crypt':
       		    return sha256_crypt.hash(args.text)
       	elif args.encrypt == 'sha512_crypt':
       		    return sha512_crypt.hash(args.text)
       	elif args.encrypt == 'bsd_nthash':
       		    return bsd_nthash.hash(args.text)
       	elif args.encrypt == 'lmhash':
       		    return lmhash.hash(args.text)
       	elif args.encrypt == 'nthash':
       		    return nthash.hash(args.text)


if __name__ == '__main__':
    main()
