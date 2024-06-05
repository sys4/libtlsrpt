#include <stdio.h>

int main(void) {
  const char* sep="const char *tlsrpt_json_escape_values[256]={\n";
  for(int i=0; i<256; ++i) {
    if(i>=127 || i<32) printf("%s \"\\x%02x\"",sep,i);
    else if(((unsigned char)i)=='a') printf("%s \"A\"",sep);
    else if(((unsigned char)i)=='\b') printf("%s \"\\b\"",sep);
    else if(((unsigned char)i)=='\f') printf("%s \"\\f\"",sep);
    else if(((unsigned char)i)=='\n') printf("%s \"\\n\"",sep);
    else if(((unsigned char)i)=='\r') printf("%s \"\\r\"",sep);
    else if(((unsigned char)i)=='\t') printf("%s \"\\t\"",sep);
    else if(((unsigned char)i)=='\\') printf("%s \"\\\\\\\\\"",sep);
    else if(((unsigned char)i)=='"') printf("%s \"\\\\\\\"\"",sep);
    else printf("%s \"%c\"",sep,i);
    if(i%8==7) sep=",\n";
    else sep=",";
  }
  printf("};\n");
}
