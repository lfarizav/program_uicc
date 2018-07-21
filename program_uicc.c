/*
  Frame work to read and write UICC cards
  Copyright (C) Laurent THOMAS, Open Cells Project

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#include <uicc.h>
#include <milenage.h>

struct uicc_vals {
  bool setIt=false;
  string adm="";
  string iccid="";
  string imsi="";
  string opc="";
  string op="";
  string isdn="";
  string acc="";
  string key="";
  string spn="open cells";
  string rusimv="";
  int mncLen=2;
  bool authenticate=false;
};

#define sc(in, out)           \
  USIMcard.send_check( string( (char*)in +37 ,sizeof(in) -37),  \
                       string( (char*)out+37 ,sizeof(out)-37) )

bool readSIMvalues(char *port) {
  SIM SIMcard;
  string ATR;
  Assert((ATR=SIMcard.open(port))!="", "Failed to open %s", port);
  //dump_hex("ATR", ATR);
  vector<string> res;
  cout << "GSM IMSI: " << SIMcard.decodeIMSI(SIMcard.readFile("IMSI")[0]) << endl;
  // Show only the first isdn (might be several)
  cout << "GSM MSISDN: " << SIMcard.decodeISDN(SIMcard.readFile("MSISDN")[0]) <<endl;
  SIMcard.close();
  return true;
}

bool readUSIMvalues(char *port) {
  vector<string> res;
  USIM USIMcard;
  string ATR;
  //printf("USIM card open is %s\n",USIMcard.open(port));
  printf("port is %s\n",port);
  //dump_hex("ATR", USIMcard.open(port));
  Assert((ATR=USIMcard.open(port))!="", "Failed to open %s", port);
  //dump_hex("ATR", ATR);
  res=USIMcard.readFile("ICCID");
  string iccid=bcdToAscii(res[0]);
  cout << "ICCID: " << iccid <<endl;

  if (!luhn( iccid))
    printf("WARNING: iccid luhn encoding of last digit not done \n");

  USIMcard.openUSIM();
  cout << "USIM IMSI: " << USIMcard.decodeIMSI(USIMcard.readFile("IMSI")[0]) << endl;
  res=USIMcard.readFile("PLMN selector with Access Technology");
  //cout << "USIM PLMN selector: " << bcdToAscii(res[0]) <<endl;
  // Show only the first isdn (might be several)
  vector<string> x=USIMcard.readFile("MSISDN");
  cout << "USIM MSISDN: " << USIMcard.decodeISDN(USIMcard.readFile("MSISDN")[0]) <<endl;
  res=USIMcard.readFile("Service Provider Name");
  cout << "USIM Service Provider Name: " << printable(res[0].substr(1)) <<endl;
  return true;
}


bool writeSIMvalues(char *port, struct uicc_vals &values) {
  vector<string> res;
  SIM USIMcard;
  string ATR;
  Assert((ATR=USIMcard.open(port))!="", "Failed to open %s", port);

  if (!USIMcard.verifyChv('\x0a', values.adm)) {
    printf("chv 0a Nok\n");
    return false;
  }

  if (values.iccid.size() > 0)
    Assert(USIMcard.writeFile("ICCID", USIMcard.encodeICCID(values.iccid)),
           "can't set iccid %s",values.iccid.c_str());

  vector<string> li;
  li.push_back("en");
  Assert(USIMcard.writeFile("Extended language preference", li), "can't set language");
  Assert(USIMcard.writeFile("language preference", makeBcdVect("01",false)), "can't set language");

  if ( values.imsi.size() > 0) {
    Assert(USIMcard.writeFile("IMSI", USIMcard.encodeIMSI(values.imsi)),
           "can't set imsi %s",values.imsi.c_str());
    string MccMnc=USIMcard.encodeMccMnc(values.imsi.substr(0,3),
                                        values.imsi.substr(3,values.mncLen));
    vector<string> VectMccMnc;
    VectMccMnc.push_back(MccMnc);
    Assert(USIMcard.writeFile("PLMN selector", VectMccMnc, true), "Can't write PLMN Selector");
    Assert(USIMcard.writeFile("Equivalent home PLMN", VectMccMnc), "Can't write Equivalent PLMN");
    vector<string> loci;
    loci.push_back(makeBcd("",true,4));
    loci[0]+=MccMnc;
    loci[0]+=makeBcd("0000ff01", false);
    Assert(USIMcard.writeFile("Location information",
                              loci), "location information");
  }

  if ( values.acc.size() > 0)
    Assert(USIMcard.writeFile("Access control class", USIMcard.encodeACC(values.acc)),
           "can't set acc %s",values.acc.c_str());

  vector<string> ad;
  ad.push_back(makeBcd("000000",false));
  ad[0]+=(char) values.mncLen;
  Assert(USIMcard.writeFile("Administrative data", ad),
         "can't set Administrative data");
  vector<string> spn;
  spn.push_back(string(u8"\x01",1));
  spn[0]+=values.spn;
  Assert(USIMcard.writeFile("Service Provider Name", spn, true), "can't set spn");
  Assert(USIMcard.writeFile("Higher Priority PLMN search period",
                            makeBcdVect("02", false)), "can't set plmn search period");
  Assert(USIMcard.writeFile("Forbidden PLMN",
                            makeBcdVect(""),true), "can't set forbidden plmn");
  Assert(USIMcard.writeFile("Group Identifier Level 1",
                            makeBcdVect(""),true), "can't set GID1");
  Assert(USIMcard.writeFile("Group Identifier Level 2",
                            makeBcdVect(""),true), "can't set GID2");
  Assert(USIMcard.writeFile("emergency call codes",
                            makeBcdVect(""),true), "can't set emergency call codes");
  // Typical service list, a bit complex to define (see 3GPP TS 51.011)
  Assert(USIMcard.writeFile("SIM service table", makeBcdVect("ff33ffff00003f033000f0c3",false)),
         "can't set GSM service table");

  if (values.isdn.size() > 0)
    Assert(USIMcard.writeFile("MSISDN",
                              USIMcard.encodeISDN(values.isdn, USIMcard.fileRecordSize("MSISDN"))),
           "can't set msisdn %s",values.isdn.c_str());

  Assert(USIMcard.writeFile("SMSC", makeBcdVect(""),true), "can't set SMS center");
  return true;
}

bool writeUSIMvalues(char *port, struct uicc_vals &values) {
  vector<string> res;
  USIM USIMcard;
  string ATR;
  Assert((ATR=USIMcard.open(port))!="", "Failed to open %s", port);
  //dump_hex("ATR", ATR);
  USIMcard.openUSIM();

  if (!USIMcard.verifyChv('\x0a', values.adm)) {
    printf("chv 0a Nok\n");
    return false;
  }

  if ( values.key.size() > 0)
    // Ki files and Milenage algo parameters are specific to the card manufacturer
    Assert(USIMcard.writeFile("GR Ki", USIMcard.encodeKi(values.key)),
           "can't set Ki %s",values.key.c_str());

  if (values.opc.size() > 0)
    Assert(USIMcard.writeFile("GR OPc", USIMcard.encodeOPC(values.opc)),
           "can't set OPc %s",values.opc.c_str());

  //Milenage internal paramters
  USIMcard.writeFile("GR R",makeBcdVect("4000204060",false));
  vector<string> C;
  C.push_back(makeBcd("00000000000000000000000000000000",false));
  C.push_back(makeBcd("00000000000000000000000000000001",false));
  C.push_back(makeBcd("00000000000000000000000000000002",false));
  C.push_back(makeBcd("00000000000000000000000000000004",false));
  C.push_back(makeBcd("00000000000000000000000000000008",false));
  USIMcard.writeFile("GR C",C);
  vector<string> li;
  li.push_back("en");
  Assert(USIMcard.writeFile("language preference", li), "can't set language");
  Assert(USIMcard.writeFile("SMSC", makeBcdVect("",true,40)),
         "can't set SMSC");

  if (values.isdn.size() > 0)
    Assert(USIMcard.writeFile("MSISDN", USIMcard.encodeISDN(values.isdn, USIMcard.fileRecordSize("MSISDN"))),
           "can't set msisdn %s",values.isdn.c_str());

  if ( values.acc.size() > 0)
    Assert(USIMcard.writeFile("Access control class", USIMcard.encodeACC(values.acc)),
           "can't set acc %s",values.acc.c_str());

  if ( values.imsi.size() > 0) {
    Assert(USIMcard.writeFile("IMSI", USIMcard.encodeIMSI(values.imsi)),
           "can't set imsi %s",values.imsi.c_str());
    string MccMnc=USIMcard.encodeMccMnc(values.imsi.substr(0,3),
                                        values.imsi.substr(3,values.mncLen));
    vector<string> VectMccMnc;
    VectMccMnc.push_back(MccMnc);
    vector<string> MccMncWithAct=VectMccMnc;
    // Add EUTRAN access techno only
    MccMncWithAct[0]+=string(u8"\x40\x00",2);
    Assert(USIMcard.writeFile("PLMN selector with Access Technology",
                              MccMncWithAct, true), "Can't write PLMN Selector");
    Assert(USIMcard.writeFile("Operator controlled PLMN selector with Access Technology",
                              MccMncWithAct, true), "Can't write Operator PLMN Selector");
    Assert(USIMcard.writeFile("Home PLMN selector with Access Technology",
                              MccMncWithAct, true), "Can't write home  PLMN Selector");
    Assert(USIMcard.writeFile("Equivalent Home PLMN",
                              VectMccMnc), "Can't write Equivalent PLMN");
    vector<string> psloci;
    psloci.push_back(makeBcd("",true,7));
    psloci[0]+=MccMnc;
    psloci[0]+=makeBcd("0000ff01", false);
    Assert(USIMcard.writeFile("PS Location information",
                              psloci,false),
           "PS location information");
    vector<string> csloci;
    csloci.push_back(makeBcd("",true,4));
    csloci[0]+=MccMnc;
    csloci[0]+=makeBcd("0000ff01", false);
    Assert(USIMcard.writeFile("CS Location information",
                              csloci, false),
           "CS location information");
  }

  vector<string> ad;
  ad.push_back(makeBcd("000000",false));
  ad[0]+=(char) values.mncLen;
  Assert(USIMcard.writeFile("Administrative data", ad),
         "can't set Administrative data");
  vector<string> spn;
  spn.push_back(string(u8"\x01",1));
  spn[0]+=values.spn;
  Assert(USIMcard.writeFile("Service Provider Name", spn, true), "can't set spn");
  Assert(USIMcard.writeFile("Higher Priority PLMN search period", makeBcdVect("02", false)), "can't set plmn search period");
  Assert(USIMcard.writeFile("Forbidden PLMNs", makeBcdVect("",true,12)), "can't set forbidden plmn");
  Assert(USIMcard.writeFile("Group Identifier Level 1", makeBcdVect("",true,4)), "can't set GID1");
  Assert(USIMcard.writeFile("Group Identifier Level 2", makeBcdVect("",true,4)), "can't set GID2");
  vector<string> ecc;
  ecc.push_back(makeBcd("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",false));
  ecc.push_back(makeBcd("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",false));
  ecc.push_back(makeBcd("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",false));
  ecc.push_back(makeBcd("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",false));
  Assert(USIMcard.writeFile("emergency call codes", ecc), "can't set emergency call codes");
  // Typical service list, a bit complex to define (see 3GPP TS 51.011)
  Assert(USIMcard.writeFile("USIM service table", makeBcdVect("867F1F1C230E0000400050", false)),
         "can't set USIM service table");
  return true;
}

static inline int makeBin(string in, string &out) {
  out="";

  if ( in.size() %2 == 1)
    return -1;

  for (size_t i=0; i<in.size(); i++) {
    uint8_t tmp=255;

    if (in[i] >= '0' && in[i]<= '9')
      tmp=in[i]-'0';

    if (in[i] >= 'a' && in[i]<= 'f')
      tmp=in[i]-'a'+10;

    if (in[i] >= 'A' && in[i]<= 'F')
      tmp=in[i]-'A'+10;

    if (tmp == 255)
      return -1;

    i++;

    if (in[i] >= '0' && in[i] <= '9') {
      out+=(unsigned char) ((in[i]-'0') | tmp <<4);
      continue;
    }

    if (in[i] >= 'a' && in[i] <= 'f') {
      out+=(unsigned char) ((in[i]-'a'+10) | tmp <<4);
      continue;
    }

    if (in[i] >= 'A' && in[i] <= 'F') {
      out+=(unsigned char) ((in[i]-'A'+10) | tmp <<4);
      continue;
    }

    return -1;
  }

  return in.size()/2;
}

void setOPc(struct uicc_vals &values) {
  string key;
  Assert(makeBin(values.key, key) == 16, "can't read a correct key: 16 hexa figures\n");
  string op;
  Assert(makeBin(values.op, op) == 16, "can't read a correct op: 16 hexa figures\n");
  uint8_t opc[16];
  milenage_opc_gen((const uint8_t *)key.c_str(),
                   (const uint8_t *)op.c_str(),
                   opc);

  for (int i=0 ; i<16; i++) {
    char tmp[8];
    sprintf(tmp,"%02hhx",opc[i]);
    values.opc+= tmp;
  }
}

void authenticate(char *port, struct uicc_vals &values) {
  string key;
  Assert(makeBin(values.key, key) == 16, "can't read a correct key: 16 hexa figures\n");
  string opc;
  Assert(makeBin(values.opc, opc) == 16, "can't read a correct opc: 16 hexa figures\n");
  USIM USIMcard;
  string ATR;
  Assert((ATR=USIMcard.open(port))!="", "Failed to open %s", port);
  //dump_hex("ATR", ATR);
  USIMcard.openUSIM();
  USIMcard.debug=false;
  // We don't make proper values for rand, sqn,
  // we perform first authentication only to get the AUTS from the USIM
  u8 amf[2]= {0};
  u8 sqn[6]= {0};
  u8 rand[16]= {0};
  u8 autn[16]= {0};
  u8 ik[16]= {0};
  u8 ck[16]= {0};
  u8 res[8]= {0};
  Assert(milenage_generate((const uint8_t *)opc.c_str(), amf,
                           (const uint8_t *)key.c_str(), sqn,
                           rand,
                           autn, ik, ck, res),
         "Milenage internal failure\n");
  string srand((char *)rand,sizeof(rand));
  string sautn((char *)autn,sizeof(autn));
  vector<string> returned=USIMcard.authenticate(srand, sautn);

  // We should have one LV value returned, the AUTS
  if (returned.size()!=1) {
    printf("The card didn't accept our challenge: OPc or Ki is wrong\n");
    return;
  }

  u8 SIMsqn[8]= {0};

  if ( ! milenage_auts((const uint8_t *)opc.c_str(),
                       (const uint8_t *)key.c_str(),
                       rand,
                       (const uint8_t *)returned[0].c_str(),
                       SIMsqn+2) ) {
    printf("Can't decode the AUTS returned by the card (wrong Ki or OPc)\n");
    return;
  }

  uint64_t intSqn=be64toh(*(uint64_t *)SIMsqn);
  intSqn+=32; // according to 3GPP TS 33.102 version 11, annex C. 3.2
  uint64_t newSqn=htobe64(intSqn);
  // To make better validation, let's generate a random value in milenage "rand"
  FILE *h=fopen("/dev/random","r");
  fread(rand,sizeof(rand),1,h);
  fclose(h);
  Assert( milenage_generate((const uint8_t *)opc.c_str(), amf,
                            (const uint8_t *)key.c_str(),
                            ((u8 *)&newSqn)+2,
                            rand,
                            autn, ik, ck, res),
          "Milenage internal failure\n");
  // Now, we can test a authentication that should be sucessful
  string new_autn((char *)autn,16);
  string new_rand((char *)rand,16);
  vector<string>  returned_newSQN=USIMcard.authenticate(new_rand, new_autn);

  if ( USIMcard.debug )
    for (size_t i=0; i< returned_newSQN.size(); i++)
      dump_hex("auth answer",returned_newSQN[i]);

  if (returned_newSQN.size() != 4)
    printf("We tried SQN %" PRId64 ", but the card refused!\n",intSqn);
  else {
    string s_ik((char *)ik,sizeof(ik));
    string s_ck((char *)ck,sizeof(ck));
    string s_res((char *)res,sizeof(res));

    if ( s_res != returned_newSQN[0] ||
         s_ck  != returned_newSQN[1] ||
         s_ik  != returned_newSQN[2] )
      printf("The card sent back vectors, but they are not our milenage computation\n");
    else {
      printf("Succeeded to authentify with SQN: %" PRId64 "\n", intSqn);
      printf("set HSS SQN value as: %" PRId64 "\n", intSqn+32 );
    }
  }
}

int main(int argc, char **argv) {
  char portName[FILENAME_MAX+1] = "/dev/ttyUSB0";
  struct uicc_vals new_vals;
  static struct option long_options[] = {
    {"port",  required_argument, 0, 0},
    {"adm",   required_argument, 0, 1},
    {"iccid", required_argument, 0, 2},
    {"imsi",  required_argument, 0, 3},
    {"opc",   required_argument, 0, 4},
    {"isdn",  required_argument, 0, 5},
    {"acc",   required_argument, 0, 6},
    {"key",   required_argument, 0, 7},
    {"MNCsize", required_argument, 0, 8},
    {"xx",    required_argument, 0, 9},
    {"authenticate",  no_argument, 0, 10},
    {"spn", required_argument, 0, 11},
    {"rusimv", required_argument, 0, 12},
    {0,       0,                 0, 0}
  };
  static map<string,string> help_text= {
    {"port",  "Linux port to access the card reader (/dev/ttyUSB0)"},
    {"adm",   "The ADM code of the card (the master password)"},
    {"iccid", "the UICC id to set"},
    {"imsi",  "The imsi to set, we automatically set complementary files such as \"home PLMN\""},
    {"opc",   "OPc field: OPerator code: must be also set in HSS (exlusive with OP)"},
    {"isdn",  "The mobile phone number (not used in simple 4G)"},
    {"acc",   "One of the defined security codes"},
    {"key",   "The authentication key (called Ki in 3G/4G, Kc in GSM), must be the same in HSS"},
    {"MNCsize","Mobile network code size in digits (default to 2)"},
    {"xx",    "OP  field: OPerator code: must be also set in HSS (exclusive with OPc)"},
    {"spn",   "service provider name: the name that the UE will show as 'network'"},
    {"rusimv",  "Read USIM values: 1 -> yes, 0 -> no"},
    {"authenticate",  "Test the milenage authentication and discover the current sequence number"},
  };
  int c;
  bool correctOpt=true;

  while (correctOpt) {
    int option_index = 0;
    c = getopt_long_only(argc, argv, "",
                         long_options, &option_index);

    if (c == -1)
      break;

    new_vals.setIt= c > 0;

    switch (c) {
      case 0:
        strncpy(portName, optarg, FILENAME_MAX);
        break;

      case 1:
        new_vals.adm=optarg;
        break;

      case 2:
        new_vals.iccid=optarg;
        break;

      case 3:
        new_vals.imsi=optarg;
        break;

      case 4:
        new_vals.opc=optarg;
        break;

      case 5:
        new_vals.isdn=optarg;
        break;

      case 6:
        new_vals.acc=optarg;
        break;

      case 7:
        new_vals.key=optarg;
        break;

      case 8:
        new_vals.mncLen=atoi(optarg);
        break;

      case 9:
        new_vals.op=optarg;
        break;

      case 10:
        new_vals.authenticate=true;
        break;

      case 11:
        new_vals.spn=optarg;
        break;
      case 12:
        new_vals.rusimv=optarg;
        break;

      default:
        printf("unrecognized option: %d \n", c);
        correctOpt=false;
    };
  }
  if (new_vals.rusimv=="1")
  {
      printf ("Read values in UICC\n");
      readUSIMvalues(portName);
  }
	
  if (optind < argc ||  correctOpt==false) {
    printf("non-option ARGV-elements: ");

    while (optind < argc)
      printf("%s ", argv[optind++]);

    printf("Possible options are:\n");

    for (int i=0; long_options[i].name!=NULL; i++)
      printf("  --%-10s %s\n",long_options[i].name, help_text[long_options[i].name].c_str());

    printf("\n");
    exit(1);
  }

  printf ("Existing values in USIM\n");
  //Assert(readUSIMvalues(portName), "failed to read UICC");

  if ( new_vals.op != "") {
    setOPc(new_vals);
    printf("Computed OPc from OP and Ki as: %s\n", new_vals.opc.c_str());
  }

  if (new_vals.setIt) {
    if ( new_vals.adm.size() ==16 )
      new_vals.adm=makeBcd(new_vals.adm);
    if ( new_vals.adm.size() != 8 )
      printf ("No ADM code of 8 figures, can't program the UICC\n");
    else {
      printf("Setting new values\n");
      writeSIMvalues(portName, new_vals);
      writeUSIMvalues(portName, new_vals);
      printf ("Read new values in UICC\n");
      readUSIMvalues(portName);
    }
  }

  if ( new_vals.authenticate)
    authenticate(portName, new_vals);

  return 0;
}
