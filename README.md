PPP OTP Authentication support
=================================

This plug-in adds support for OTP time based tokens for pppd PPP server.
Compatible with Google Authenticator software token or software/hardware based OTP tokens.

Compile and install otp.so file to your PPP daemon plugins directory and add it to your pppd config:

    # use otp passwords
    plugin otp.so

The plugin supports following options (default values specified):

    # Path to otp secrets file
    otp_secrets /etc/ppp/otp-secrets
    
    # Maximum allowed clock slop
    otp_slop 180
    
    # T0 value for TOTP (time drift)
    totp_t0 0
    
    # Step value for TOTP
    totp_step 30
    
    # Number of digits to use from TOTP hash
    totp_digits 6
    
    # Step value for MOTP 
    motp_step 10

The otp-secrets file format is as follows:

    # user server type:hash:encoding:key:pin:udid client
    # where type is topt or mopt
    #       hash should be sha1 in most cases
    #       encoding is base32 or text
    #       key is your key in encoding format
    #       pin is a 4 digit pin
    #       udid is used in motp mode
    #
    # use sha1/base32 for Google Authenticator
    bob otp topt:sha1:base32:K7BYLIU5D2V33X6S:1234:xxx *
    
    # use text encoding for text based format
    jane otp topt:sha1:text:1234567890:9876:xxx *
    
When users dial in, they will need to provide their username and pin+current OTP number from the OTP token. Example for user bob:

    username: bob
    password: 1234920151

Originally written by GitHub User kolbyjack
This instruction and Base32 support added by Evgeny Gridasov (evgeny.gridasov@gmail.com) 

