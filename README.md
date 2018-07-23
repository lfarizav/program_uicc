# program_uicc
Software to read/write USIM

# Possible options are:
1.  --port       Linux port to access the card reader (/dev/ttyUSB0)
2.  --adm        The ADM code of the card (the master password is 85496936)
3.  --iccid      the UICC id to set
4.  --imsi       The imsi to set, we automatically set complementary files such as "home PLMN"
5.  --opc        OPc field: OPerator code: must be also set in HSS (exlusive with OP)
6.  --isdn       The mobile phone number (not used in simple 4G)
7.  --acc        One of the defined security codes
8.  --key        The authentication key (called Ki in 3G/4G, Kc in GSM), must be the same in HSS
9.  --MNCsize    Mobile network code size in digits (default to 2)
10.  --xx         OP  field: OPerator code: must be also set in HSS (exclusive with OPc)
11.  --authenticate Test the milenage authentication and discover the current sequence number
12.  --spn        service provider name: the name that the UE will show as 'network'
13.  --rusimv     Read USIM values: 1 -> yes, 0 -> no

