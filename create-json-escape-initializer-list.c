/*
    Copyright (C) 2024-2025 sys4 AG
    Author Boris Lohner bl@sys4.de

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

void print_license() {
  printf("/*\n\
    Copyright (C) 2024-2025 sys4 AG\n\
    Author Boris Lohner bl@sys4.de\n\
\n\
    This program is free software: you can redistribute it and/or modify\n\
    it under the terms of the GNU Lesser General Public License as\n\
    published by the Free Software Foundation, either version 3 of the\n\
    License, or (at your option) any later version.\n\
\n\
    This program is distributed in the hope that it will be useful,\n\
    but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
    GNU Lesser General Public License for more details.\n\
\n\
    You should have received a copy of the GNU Lesser General Public\n\
    License along with this program.\n\
    If not, see <http://www.gnu.org/licenses/>.\n\
 */\n\
\n\
");
}

int main(void) {
  print_license();
  const char* sep="const char *tlsrpt_json_escape_values[256]={\n";
  for(int i=0; i<256; ++i) {
    if(((unsigned char)i)=='\b') printf("%s \"\\\\b\"",sep);
    else if(((unsigned char)i)=='\f') printf("%s \"\\\\f\"",sep);
    else if(((unsigned char)i)=='\n') printf("%s \"\\\\n\"",sep);
    else if(((unsigned char)i)=='\r') printf("%s \"\\\\r\"",sep);
    else if(((unsigned char)i)=='\t') printf("%s \"\\\\t\"",sep);
    else if(((unsigned char)i)=='\\') printf("%s \"\\\\\\\\\"",sep);
    else if(((unsigned char)i)=='"') printf("%s \"\\\\\\\"\"",sep);
    else if(i==127 || i<32) printf("%s \"\\\\u%04x\"",sep,i);
    else if(i>127) printf("%s \"\\x%02x\"",sep,i);
    else printf("%s \"%c\"",sep,i);
    if(i%8==7) sep=",\n";
    else sep=",";
  }
  printf("};\n");
}
