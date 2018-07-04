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

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <numeric>


using namespace std;
/*
  Copyright: Open cells company
  Author:    Laurent Thomas

  Specification of UICC dialog: ETSI TS 102 221
  Specification of UICC files management: ETSI TS 102 222

*/

/*  ETSI TS 102 221
  Coding of Instruction Byte of the Commands
  for a telecom application
  SELECT FILE '0X' or '4X' or '6X' 'A4'
  STATUS '8X' or 'CX' or 'EX' 'F2'
  READ BINARY '0X' or '4X' or '6X' 'B0'
  UPDATE BINARY '0X' or '4X' or '6X' 'D6'
  READ RECORD '0X' or '4X' or '6X' 'B2'
  UPDATE RECORD '0X' or '4X' or '6X' 'DC'
  SEARCH RECORD '0X' or '4X' or '6X' 'A2'
  INCREASE '8X' or 'CX' or 'EX' '32'
  RETRIEVE DATA '8X' or 'CX' or 'EX' 'CB'
  SET DATA '8X' or 'CX' or 'EX' 'DB'
  VERIFY '0X' or '4X' or '6X' '20'
  CHANGE PIN '0X' or '4X' or '6X' '24'
  DISABLE PIN '0X' or '4X' or '6X' '26'
  ENABLE PIN '0X' or '4X' or '6X' '28'
  UNBLOCK PIN '0X' or '4X' or '6X' '2C'
  DEACTIVATE FILE '0X' or '4X' or '6X' '04'
  ACTIVATE FILE '0X' or '4X' or '6X' '44'
  AUTHENTICATE '0X' or '4X' or '6X'     '88', '89'
  GET CHALLENGE '0X' or '4X' or '6X' '84'
  TERMINAL CAPABILITY '8X' or 'CX' or 'EX' 'AA'
  TERMINAL PROFILE '80' '10'
  ENVELOPE '80''C2'
  FETCH  '80'   '12'
  TERMINAL RESPONSE   '80'  '14'
  MANAGE CHANNEL '0X' or '4X' or '6X' '70'
  MANAGE SECURE CHANNEL '0X' or '4X' or '6X' '73'
  TRANSACT DATA '0X' or '4X' or '6X' '75'
  GET RESPONSE '0X' or '4X' or '6X' 'C0'
*/

#define Assert(cOND, fORMAT, aRGS...)         \
  do {                  \
    if ( !(cOND) ) {                                          \
      fprintf(stderr, "\nAssertion ("#cOND") failed!\n"   \
              "In %s() %s:%d, \nSystem error: %s\nadditional txt: " fORMAT "\nExiting execution\n" ,\
              __FUNCTION__, __FILE__, __LINE__,  strerror(errno), ##aRGS); \
      fflush(stdout);             \
      fflush(stderr);             \
      exit(EXIT_FAILURE);           \
    }                 \
  } while(0)

static inline string extractTLV(string in, string TLVname) {
  static const map<string,char> Tags= {
    {"Application Template", '\x61'},
    {"FCP Template", '\x62'},
    {"AID", '\x4f'},
    {"Card", '\x50' },
    {"File Size - Data", '\x80'},
    {"File Size - Total", '\x81'},
    {"File Descriptor", '\x82'},
    {"File Identifier", '\x83'},
    {"DF Name (AID)", '\x85'},
    {"Life Cycle Status", '\x8a'},
    {"Security attribute data", '\x8b'},
    {"SFI", '\x88'},
  };
  auto it=Tags.find(TLVname);

  if (it != Tags.end()) {
    char tag=it->second;
    size_t index=0;

    while (index < in.size()) {
      if (in[index]==tag)
        return in.substr(index+2, (unsigned)in[index+1]);

      index+=in[index+1]+2;
    }
  }

  return "";
}

static inline void dump_hex(string name, string data) {
  printf("%s: 0x", name.c_str());

  for (size_t i=0; i<data.size(); i++)
    printf("%02hhx", data[i]);

  printf("\n");
}

static inline string bcdToAscii(string data) {
  string ret="";

  for (size_t i=0; i<data.size(); i++) {
    char c= (data[i] & 0xF) + '0';

    if ( c >= '0' && c <= '9' )
      ret+=c;

    c= (data[i]>>4 & 0xF) + '0';

    if ( c >= '0' && c <= '9' )
      ret+=c;
  }

  return ret;
}

static inline unsigned char mkDigit(unsigned char in) {
  unsigned char v=tolower(in);

  if ( v >= '0'&& v <= '9' )
    return v-'0';

  if ( v >= 'a'&& v <= 'f' )
    return v-'a'+10;

  printf("Invalid hexa value: %x \n", (int)in);
  return 0;
}

static inline string makeBcd(string data, bool swap=true, int outputLength=0) {
  string tmp=data;
  string output;

  if (data.size()%2 == 1 )
    tmp+='f';

  if (swap)
    for(size_t i=0; i< tmp.size(); i+=2)
      output+=(char)( (mkDigit(tmp[i+1])<<4) + (mkDigit(tmp[i])) );
  else
    for(size_t i=0; i< tmp.size(); i+=2)
      output+=(char)( (mkDigit(tmp[i])<<4) + (mkDigit(tmp[i+1])) );

  for (int i=tmp.size()/2; i<outputLength; i++)
    output+='\xff';

  return output;
}

static inline vector<string> makeBcdVect(string data, bool swap=true, int outputLength=0) {
  vector<string> out;
  out.push_back(makeBcd(data, swap, outputLength));
  return out;
}

static inline string printable(string in) {
  string ret="";

  for (auto c:in )
    if(isprint(c))
      ret+=c;

  return ret;
}

static inline bool luhn( const string &id) {
  static const int m[10]  = {0,2,4,6,8,1,3,5,7,9}; // mapping for rule 3
  bool is_odd_dgt = false;
  auto lambda = [&](int a, char c) {
    return a + ((is_odd_dgt = !is_odd_dgt) ? c-'0' : m[c-'0']);
  };
  int s = std::accumulate(id.rbegin(), id.rend(), 0, lambda);
  return 0 == s%10;
}

class UICC {
 public:
  UICC() {
    char *debug_env=getenv("DEBUG");

    if (debug_env != NULL &&
        (debug_env[0] == 'Y' || debug_env[0] == 'y'))
      debug=true;
  };
  ~UICC() {
    close();
  };

  string read(size_t s = 1024) {
    size_t got=0;
    string data="";

    while (got < s) {
      int ret;
      char buf;
      Assert( (ret=::read(fd, &buf, 1)) >= 0, "Error from read");

      switch (ret) {
        case 1:
          got++;
          data+=buf;
          break;

        case 0: // for time out: no more data
          if (debug)
            dump_hex("Received", data);

          return data;
          break;

        default:
          fprintf(stderr,"Error from read > 1 char\n");
      }
    }

    if (debug)
      dump_hex("Received", data);

    return data;
  }

  int write(string buf) {
    if (debug)
      dump_hex("Sending", buf);

    size_t size=buf.size();
    Assert( size >= 5, "");

    for (int i=0; i<5; i++ ) {
      ::write(fd, &buf[i], 1);
      // UICC have only one wire for Tx and Rx,
      // so over a RS232 we always receive back what we send
      char c;
      Assert(::read(fd, &c, 1)==1,
             "All data sent must echo back" );
    }

    // Read UICC acknowledge the order
    if (buf[0] == (int8_t)'\xa0'|| buf[0] == (int8_t)'\x00' ) {
      char c;
      int ret=::read(fd, &c, 1);
      Assert( ret ==1 && c == buf[1],
              "UICC answer is %02hhx instead of %02hhx",c, buf[1]);
    } else
      printf("WARNING: Non standard packet sent\n");

    for (size_t i=5; i<size; i++ ) {
      ::write(fd, &buf[i], 1);
      char c;
      Assert(::read(fd, &c, 1)==1,
             "All data sent must echo back" );
    }

    return size;
  }

  // Returns the ATR (answer to reset) string
  string open(char *portname) {
    Assert( (fd=::open(portname, O_RDWR | O_NOCTTY | O_SYNC)) >=0,
            "Failed to open %s", portname);
    struct termios tty;
    Assert (tcgetattr(fd, &tty) >= 0, "");
    tty.c_cflag &= ~( CSIZE );
    tty.c_cflag |= CLOCAL | CREAD | CS8 | PARENB | CSTOPB | HUPCL ;
    /* setup for non-canonical mode */
    tty.c_iflag &= ~(IGNBRK | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_oflag &= ~OPOST;
    /* fetch bytes as they become available */
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 1;
    cfsetispeed(&tty, (speed_t)B9600);
    cfsetospeed(&tty, (speed_t)B9600);
    Assert (tcsetattr(fd, TCSANOW, &tty) == 0,"");
    // reset the UICC
    int iFlags;
    iFlags = 0 ;
    // turn off DTR
    ioctl(fd, TIOCMSET, &iFlags);
    struct timespec t= {0,1000*1000*100};
    nanosleep(&t,NULL);
    iFlags = 0xFFFF;
    // turn on DTR
    //iFlags = TIOCM_CTS  ;
    //ioctl(fd, TIOCMSET, &iFlags);
    return this->read();
  }

  void close() {
    if (fd!=-1)
      ::close(fd);

    fd=-1;
  }

  bool send_check( string in, string out) {
    Assert( write(in) == (int)in.size(), "");
    string answer=read(out.size());

    if (answer.size() != out.size()) {
      printf("ret is not right size\n");
      dump_hex("expect", out);
      dump_hex("answer", answer);
      return false;
    }

    if ( answer != out) {
      printf("BAD return code\n");
      string answer2=read(255);
      dump_hex("Expected: ", out);
      dump_hex("got answer: ", answer+answer2);
      return false;
    }

    return true;
  }

  bool verifyChv(char cla, char chv, string pwd) {
    string order;
    order+=cla;
    order+=string(u8"\x20\x00",2);
    order+=chv;
    order+=(char)8;
    order+=pwd;

    for (int i=pwd.size(); i<8 ; i++)
      order+='\xff';

    string answer (u8"\x90\x00",2);
    return send_check(order, answer);
  }

  bool updateChv(char cla, char chv, string oldpwd, string newpwd) {
    string order;
    order+=cla;
    order+=string(u8"\x24\x00",2);
    order+=chv;
    order+=(char)16;
    order+=oldpwd;

    for (int i=oldpwd.size(); i<8 ; i++)
      order+='\xff';

    order+=newpwd;

    for (int i=newpwd.size(); i<8 ; i++)
      order+='\xff' ;

    string answer (u8"\x90\x00",2);
    return send_check(order, answer);
  }

  string decodeISDN(string raw) {
    // ISDN is in last 14 bytes
    string isdn=raw.substr(raw.size()-14);
    char isdnLength=isdn[0];
    //char TON=isdn[1]; // should be 0x81
    // two last bytes should be FF (capability , extensions)
    return bcdToAscii(isdn.substr(2,isdnLength));
  }

  vector<string> encodeISDN(string isdn, int recordLenght) {
    vector<string> encoded;
    encoded.push_back("");

    for (int i=0; i < recordLenght-14 ; i++)
      encoded[0]+='\xff';

    encoded[0]+=makeBcd(isdn).size();
    encoded[0]+='\x81'; //add TON field
    encoded[0]+=makeBcd(isdn);

    for (int i=encoded.size(); i<recordLenght; i++)
      encoded[0]+='\xff';

    return encoded;
  }

  string decodeIMSI(string raw) {
    //int l=raw.c_str()[0];
    string imsi=bcdToAscii(raw.substr(1)); // First byte is length
    //IMSI length bytes, then parity is second byte
    return imsi.substr(1);
  }

  string encodeMccMnc(string Mcc, string Mnc, int len=0) {
    string out;
    out=makeBcd(Mcc);
    out+=makeBcd(Mnc, true, len>2?len-2:0);
    return out;
  }

  vector<string> encodeIMSI(string imsi) {
    vector<string> encoded;
    encoded.push_back("");

    if (imsi.size() %2 ==1 ) {
      encoded[0]+=(char)(imsi.size()/2 + 1);
      encoded[0]+=(char)(9 | (imsi[0]-'0')<<4);
    } else {
      encoded[0]+=(char)(imsi.size()/2);
      encoded[0]+=(char)(1 | (imsi[0]-'0')<<4);
    }

    encoded[0]+=makeBcd(imsi.substr(1));
    return encoded;
  }

  vector<string> encodeOPC(string in) {
    return makeBcdVect(in,false);
  }
  vector<string> encodeACC(string in) {
    return makeBcdVect(in,false);
  }
  vector<string> encodeKi(string in) {
    return makeBcdVect(in,false);
  }
  vector<string> encodeICCID(string in) {
    return makeBcdVect(in,true,10);
  }

  bool debug=false;

 private:

  int fd=-1;
};

class SIM: public UICC {
 private:

  typedef struct fileChar_s {
    uint16_t rfu;
    uint16_t size;           // total size
    uint16_t id;             // file name
    uint8_t  type;           // 01=MF, 02=DF, 04=EF
    uint8_t  cyclic_variant; //
    uint8_t  access[3];      //
    uint8_t  status;         // usage when invalidated
    uint8_t  length_following; //
    uint8_t  structure;      // 00=binary, 01=linear, 03=cyclic
    uint8_t record_length;   // provided only for linear and cyclic files
  } __attribute__ ((packed)) GSMfileChar_t;
  GSMfileChar_t curFile;

  string UICCFile(string name, bool reverse=false) {
    static const map<string,string> UICCFiles = {
      {"EFDIR", string(u8"\x2f\x00",2)},
      {"ICCID", string(u8"\x2f\xe2",2)},
      {"GR type",   string(u8"\xa0\x00",2)},
      {"Extended language preference", string(u8"\x2f\x05",2)},
      {"language preference", string(u8"\x7f\x20\x6f\x05",4)},
      {"IMSI", string(u8"\x7f\x20\x6f\x07",4)},
      {"Access control class", string(u8"\x7f\x20\x6f\x78",4)},
      {"Location information", string(u8"\x7f\x20\x6f\x7e",4)},
      {"Administrative data", string(u8"\x7f\x20\x6f\xad",4)},
      {"Service Provider Name", string(u8"\x7f\x20\x6f\x46",4)},
      {"PLMN selector", string(u8"\x7f\x20\x6f\x30",4)},
      {"Higher Priority PLMN search period", string(u8"\x7f\x20\x6f\x31",4)},
      {"Forbidden PLMN", string(u8"\x7f\x20\x6f\x7b",4)},
      {"Equivalent home PLMN", string(u8"\x7f\x20\x6f\xd9",4)},
      {"Group Identifier Level 1", string(u8"\x7f\x20\x6f\x3e",4)},
      {"Group Identifier Level 2", string(u8"\x7f\x20\x6f\x3f",4)},
      {"emergency call codes",  string(u8"\x7f\x20\x6f\xb7",4)},
      {"SIM service table", string(u8"\x7f\x20\x6f\x38",4)},
      {"ACM maximum value", string(u8"\x7f\x20\x6f\x37",4)},
      {"Accumulated call meter", string(u8"\x7f\x20\x6f\x39",4)},
      {"Phase identification", string(u8"\x7f\x20\x6f\xae",4)},
      {"HPLMN Selector with Access Technology", string(u8"\x7f\x20\x6f\x62",4)},
      {"MSISDN", string(u8"\x7f\x10\x6f\x40",4)},
      {"SMSC", string(u8"\x7f\x10\x6f\x42",4)},
      {"GR OPc", string(u8"\x7f\xf0\xff\x01",4)},
      {"GR Ki",  string(u8"\x7f\xf0\xff\x02",4)},
      {"GR R",   string(u8"\x7f\xf0\xff\x03",4)},
      {"GR C",   string(u8"\x7f\xf0\xff\x04",4)},
      {"GR secret",   string(u8"\x7f\x20\x00\x01",4)},
    };

    if (!reverse ) {
      auto it=UICCFiles.find(name);
      Assert( it != UICCFiles.end(),   "try to access not defined file: %s", name.c_str());
      return(it->second);
    } else {
      for (auto it = UICCFiles.begin(); it != UICCFiles.end(); ++it )
        if (it->second.substr(it->second.size()-2) == name)
          return it->first;

      return "Not existing";
    }
  }

 public:
  bool readFileInfo() {
    string order(u8"\xa0\xc0\x00\x00\x0f",5);
    string good(u8"\x90\x00",2);
    write(order);
    string values=read();
    memcpy(&curFile,values.c_str(),
           min(values.size(),sizeof(curFile)) );

    if (debug) {
      static map<char, string> FileType= {{'\x01',"Master dir"}, {'\x02',"Sub dir"},{'\x04',"Element File"},};
      string fName=UICCFile(string((char *)&curFile.id,2),true);
      printf("File: %s, type: %s ",
             fName.c_str(),
             FileType[curFile.type].c_str());

      if ( curFile.type == 4 ) {
        static map<char, string> FileAccess= {{'\x00',"Always"},{'\x01',"Pin1"},{'\x02',"Pin2"},{'\x03',"RFU"},{'\x04',"ADM"},{'\x0e',"ADM"},{'\x0F',"Never"}, {'\x0a',"GR"}};
        static map<char, string> FileType= {{'\x00',"Transparent"},{'\x01',"Linear Fixed"},{'\x03',"Cyclic"}};
        printf("Type: %s, Access: read=%x (%s), update=%x (%s), size %hu\n",
               FileType[curFile.structure].c_str(),
               curFile.access[0]>>4,
               FileAccess[curFile.access[0]>>4].c_str(),
               curFile.access[0]&0xf,
               FileAccess[curFile.access[0]&0xf].c_str(),
               ntohs(curFile.size)
              );
      } else
        printf("\n");
    }

    return values.substr(values.size()-2) == good;
  }

  bool openFile(string filename) {
    string order(u8"\xa0\xa4\x00\x00\x02",5);
    // go to root directory (MF)
    string goToRoot (u8"\x3f\x00",2);
    string answerChangeDir(u8"\x9f\x17",2);

    if (!send_check(order+goToRoot, answerChangeDir))
      return false;

    string answer(u8"\x9f\x0f",2);
    string filenameBin=UICCFile(filename);

    for (size_t i=0; i<filenameBin.size()-2; i+=2)
      if (!send_check(order+filenameBin.substr(i,2), answerChangeDir))
        return false;

    if (! send_check(order+filenameBin.substr(filenameBin.size()-2), answer))
      return false;

    return readFileInfo();
  }

  vector<string> readFile(string filename) {
    vector<string> content;

    if (!openFile(filename))
      return content;

    uint16_t size=ntohs(curFile.size);

    if (ntohs(curFile.structure)==0) { // binary (flat)
      Assert(size <= 256, "Not developped: read binary files > 256 bytes (%hu)", size);
      string command(u8"\xa0\xb0\x00\x00",4);
      string good(u8"\x90\x00",2);
      char s=size&0xFF;
      command+=string(&s,1);
      write(command);
      string answ=read(size+good.size());

      if ( answ.size()==(size_t)size+2 &&
           answ.substr(answ.size()-2) == good )
        content.push_back(answ.substr(0,answ.size()-2));

      return content;
    } else { // records
      for (int i=0; i < size/curFile.record_length; i++ ) {
        string command(u8"\xa0\xb2\x00\x02",4);
        string good(u8"\x90\x00",2);
        command+=string((char *)&curFile.record_length,1);
        write(command);
        string answ=read(size+good.size());

        if ( answ.size()==(size_t)curFile.record_length+good.size() &&
             answ.substr(answ.size()-2) == good )
          content.push_back(answ.substr(0,answ.size()-good.size()));
      }

      return content;
    }
  }

  bool writeFile(string filename, vector<string> content, bool fillIt=false,  bool records=false) {
    if (!openFile(filename))
      return false;

    unsigned char size=( unsigned char)content[0].size();
    uint16_t fileSize=ntohs(curFile.size);

    if (curFile.structure==0 && records==false) { // binary (flat)
      Assert(size <= 256, "Not developped: write binary files > 256 bytes");
      string command(u8"\xa0\xd6\x00\x00",4);
      string good(u8"\x90\x00",2);

      if (fillIt)
        command+=( unsigned char)fileSize;
      else
        command+=size;

      command+=content[0];

      if (fillIt)
        for (int j=size; j < fileSize; j++)
          command+=u8"\xff";

      write(command);
      string answ=read(good.size());

      if (answ == good)
        return true;
      else
        return false;
    } else { // records
      for (size_t i=0; i < content.size(); i++ ) {
        string command(u8"\xa0\xdc",2);
        string good(u8"\x90\x00",2);
        command+=(unsigned char) i+1;
        command+='\x04';
        command+=curFile.record_length; //record lenght;
        command+=content[i];

        for (int j=content[i].size(); j< curFile.record_length ; j++)
          command+=u8"\xff";

        write(command);
        string answ=read(good.size());

        if ( answ != good )
          return false;
      }
    }

    return true;
  }

  int fileRecordSize(string filename) {
    openFile(filename);
    return curFile.record_length;
  }

  bool verifyChv(char chv, string pwd) {
    return UICC::verifyChv('\xa0', chv, pwd);
  }

  bool updateChv(char chv, string oldpwd, string newpwd) {
    return UICC::updateChv('\xa0', chv, oldpwd, newpwd);
  }

};

class USIM: public UICC {
 private:
  string UICCFile(string name) {
    static const map<string,string> UICCFiles = {
      {"EFDIR", string(u8"\x2f\x00",2)},
      {"ICCID", string(u8"\x2f\xe2",2)},
      {"Extended language preference", string(u8"\x2f\x05",2)},
      {"language preference", string(u8"\x7f\x20\x6f\x05",4)},
      {"SMSC", string(u8"\x7f\x10\x6f\x42",4)},
      {"IMSI", string(u8"\x7f\xf0\x6f\x07",4)},
      {"Access control class", string(u8"\x7f\xf0\x6f\x78",4)},
      {"PS Location information", string(u8"\x7f\xf0\x6f\x73",4)},
      {"CS Location information", string(u8"\x7f\xf0\x6f\x7e",4)},
      {"Administrative data", string(u8"\x7f\xf0\x6f\xad",4)},
      {"PLMN selector with Access Technology", string(u8"\x7f\xf0\x6f\x60",4)},
      {"Operator controlled PLMN selector with Access Technology", string(u8"\x7f\xf0\x6f\x61",4)},
      {"Home PLMN selector with Access Technology", string(u8"\x7f\xf0\x6f\x62",4)},
      {"Forbidden PLMNs", string(u8"\x7f\xf0\x6f\x7b",4)},
      {"Higher Priority PLMN search period", string(u8"\x7f\xf0\x6f\x31",4)},
      {"Equivalent Home PLMN", string(u8"\x7f\xf0\x6f\xd9",4)},
      {"Group Identifier Level 1", string(u8"\x7f\xf0\x6f\x3e",4)},
      {"Group Identifier Level 2", string(u8"\x7f\xf0\x6f\x3f",4)},
      {"emergency call codes",  string(u8"\x7f\xf0\x6f\xb7",4)},
      {"Short Message Service Parameters", string(u8"\x7f\xf0\x6f\x42",4)},
      {"Service Provider Name", string(u8"\x7f\xf0\x6f\x46",4)},
      {"EPS LOCation Information", string(u8"\x7f\xf0\x6f\xe3",4)},
      {"EPS NAS Security Contex", string(u8"\x7f\xf0\x6f\xe4",4)},
      {"MSISDN", string(u8"\x7f\xf0\x6f\x40",4)},
      {"USIM service table", string(u8"\x7f\xf0\x6f\x38",4)},
      {"GR OPc", string(u8"\x7f\xf0\xff\x01",4)},
      {"GR Ki",  string(u8"\x7f\xf0\xff\x02",4)},
      {"GR R",   string(u8"\x7f\xf0\xff\x03",4)},
      {"GR C",   string(u8"\x7f\xf0\xff\x04",4)},
      {"GR secret",   string(u8"\x7f\x20\x00\x01",4)},
    };
    auto it=UICCFiles.find(name);
    Assert( it != UICCFiles.end(),   "try to access not defined file: %s", name.c_str());
    return(it->second);
  }
  string fileInfo;
  string fileDesc;
  int fileSize;

 public:
  bool readFileInfo(string size) {
    string order(u8"\x00\xc0\x00\x00",4);
    order+=size;
    string good(u8"\x90\x00",2);
    write(order);
    string values=read(size[0] +good.size());

    if ( values[0] != '\x62' || values.substr(values.size()-2) != good)
      return false;

    fileInfo=extractTLV(values, "FCP Template");
    fileDesc=extractTLV(fileInfo, "File Descriptor");
    string fileSizeString=extractTLV(fileInfo, "File Size - Data");
    fileSize=0;

    for (size_t i=0; i<fileSizeString.size(); i++)
      fileSize=fileSize*256+(unsigned char)fileSizeString[i];

    return true;
  }

  bool openFile(string filename) {
    string order(u8"\x00\xa4\x08\x04",4);
    string answer(u8"\x61",1);
    string filenameBin=UICCFile(filename);

    if (! send_check(order+(char)(filenameBin.size())+filenameBin, answer))
      return false;

    string size=read(1);

    if (size.size() !=1)
      return false;

    return readFileInfo(size);
  }

  vector<string> readFile(string filename) {
    vector<string> content;

    if (!openFile(filename))
      return content;

    if (fileDesc.size() <= 2 ) { // this is a plain file
      long size=fileSize;
      string fullanswr="";
      Assert( size < 32767, "Not developped");
      long alreadyRead=0;

      while (size > 0 ) {
        string command(u8"\x00\xb0",2);
        string good(u8"\x90\x00",2);
        unsigned char s;

        if (size > 255)
          s=255;
        else
          s=size;

        unsigned char P1=alreadyRead>>8;
        unsigned char P2=alreadyRead&0xFF;
        command+=string((char *)&P1,1);
        command+=string((char *)&P2,1);
        command+=string((char *)&s,1);
        write(command);
        string answ=read(s+2);

        if ( answ.size()==(size_t)s+good.size() &&
             answ.substr(answ.size()-good.size()) == good )
          fullanswr+=answ.substr(0,answ.size()-good.size());

        size-=s;
        alreadyRead+=s;
      }

      content.push_back(fullanswr);
      return content;
    } else {
      // This is a records set file
      // records
      // string len must be 5 bytes
      // file type is byte 0
      // byte 1 is useless: always 0x21
      // bytes 3 and 4: record length
      // (byte 3 should be 00 according to ETSI 102 221)
      // byte 5: number of records
      for (int i=0; i < (unsigned char)fileDesc[4] ; i++ ) {
        string command(u8"\x00\xb2\x01\x04",4);
        string good(u8"\x90\x00",2);
        command+=fileDesc.substr(3,1);
        write(command);
        string answ=read( (unsigned char)fileDesc[3]+2);

        if ( answ.size()== ((unsigned char)fileDesc[3]+good.size()) &&
             answ.substr(answ.size()-good.size()) == good )
          content.push_back(answ.substr(0,answ.size()-good.size()));
      }

      return content;
    }
  }

  bool writeFile(string filename, vector<string> content, bool fillIt=false, bool records=false) {
    if (!openFile(filename))
      return false;

    int size=content[0].size();

    if (fileDesc.size() <= 2) { // binary (flat)
      Assert(size <= 256, "Not developped: write binary files > 256 bytes");
      string command(u8"\x00\xd6\x00\x00",4);
      string good(u8"\x90\x00",2);
      unsigned char x=(char) size;

      if (fillIt)
        command+=(unsigned char)fileSize;
      else
        command+=x;

      command+=content[0];

      if (fillIt)
        for (int j=content[0].size();
             j< (unsigned char) fileSize ;
             j++)
          command+=u8"\xff";

      write(command);
      string answ=read(good.size());

      if (answ == good)
        return true;
      else
        return false;
    } else { // records
      for (size_t i=0; i < content.size(); i++ ) {
        string command(u8"\x00\xdc",2);
        string good(u8"\x90\x00",2);
        command+=(unsigned char) i+1;
        command+='\x04';
        command+=fileDesc.substr(3,1); //record lenght;
        command+=content[i];

        for (int j=content[i].size();
             j< (unsigned char) fileDesc[3] ;
             j++)
          command+=u8"\xff";

        write(command);
        string answ=read(good.size());

        if ( answ != good )
          return false;
      }
    }

    return true;
  }

  bool verifyChv(char chv, string pwd) {
    return UICC::verifyChv('\x00', chv, pwd);
  }

  bool updateChv(char chv, string oldpwd, string newpwd) {
    return UICC::updateChv('\x00', chv, oldpwd, newpwd);
  }

  bool openUSIM() {
    vector<string> res;
    // Read card description
    res=readFile("EFDIR");
    string Appli=extractTLV(res[0], "Application Template");
    string AID=extractTLV(Appli, "AID");
    //Instead of first AID, we should look for AID starting by: a000000087 (3GPP) 1002 (USIM)
    //dump_hex("AID", AID);
    //printf("card supplier id: %s\n", extractTLV(Appli, "Card").c_str());
    string order(u8"\x00\xa4\x04\x0c",4);
    order+=(char)AID.size();
    order+=AID;
    string answer (u8"\x90\x00",2);
    return send_check(order, answer);
  }

  int fileRecordSize(string filename) {
    openFile(filename);

    if (fileDesc.size() <= 2)
      return -1;

    return fileDesc[3];
  }

  vector<string> authenticate(string rand, string autn) {
    vector<string> ret;
    string order(u8"\x00\x88\x00\x81",4);
    order+=(unsigned char) (rand.size()+autn.size()+2);
    order+=(unsigned char) rand.size();
    order+=rand;
    order+=(unsigned char) autn.size();
    order+=autn;
    string answerKeys(u8"\x61",1);
    string answerAUTS(u8"\x9f",1);
    Assert(write(order)==(int)order.size(),"");
    // Cards need CPU procesing, so delay to check Milenage
    sleep(1);
    string answer=read(1);

    if ( answer != answerKeys && answer != answerAUTS) {
      printf("Not possible answer to milenage challenge: %x\n", answer[0]);
      return ret;
    }

    string size=read(1);

    if (size.size() !=1) {
      printf("No answer to mileange challenge\n");
      return ret;
    }

    string getData(u8"\x00\xc0\x00\x00",4);
    getData+=size;
    string good(u8"\x90\x00",2);
    write(getData);
    string values=read(size[0] + good.size());

    if ( values.substr(values.size()-2) != good) {
      printf("Can't get APDU in return of millenage challenge\n");
      return ret;
    }

    if (values[0] == '\xDC' ) // we have a AUTS answer encoded as len+val
      ret.push_back(values.substr(2,values[1]));

    if (values[0] == '\xDB' ) { //we have the keys
      size_t pos=1;

      while (pos < values.size()-2 ) {
        ret.push_back(values.substr(pos+1,values[pos]));
        pos+=values[pos]+1;
      }
    }

    return ret;
  }
};
