# program_uicc
Software to read/write USIM

# Possible options are:
  --port       Linux port to access the card reader (/dev/ttyUSB0)
  --adm        The ADM code of the card (the master password is 85496936)
  --iccid      the UICC id to set
  --imsi       The imsi to set, we automatically set complementary files such as "home PLMN"
  --opc        OPc field: OPerator code: must be also set in HSS (exlusive with OP)
  --isdn       The mobile phone number (not used in simple 4G)
  --acc        One of the defined security codes
  --key        The authentication key (called Ki in 3G/4G, Kc in GSM), must be the same in HSS
  --MNCsize    Mobile network code size in digits (default to 2)
  --xx         OP  field: OPerator code: must be also set in HSS (exclusive with OPc)
  --authenticate Test the milenage authentication and discover the current sequence number
  --spn        service provider name: the name that the UE will show as 'network'
  --rusimv     Read USIM values: 1 -> yes, 0 -> no

