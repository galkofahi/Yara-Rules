rule Hunting_Stealer_Qbot_dll_File {
   meta:
      
      description = "Detects Stealer_Qbot_dll_File"
      author = "@galkofahi"
      date = "2022-11-17"
      Hash = "2cb8f04d41fe34706ff61cba06788faaaca87494721fcf8e86d20b897890a3b1"
      OS = "Windows"
      
   strings:
      $str1 = "? ?(?0?8?@?H?P?X?`?h?p?x?" ascii fullword
      $first_a = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 } // first bytes in the header.
      $entry_b = { 55 8B EC 83 7D 0C 01 75 05 E8 F9 08 00 00 FF 75 10 FF 75 0C FF 75 08 E8 BE FE FF FF 83 C4 0C 5D C2 } // entry-point (IMAGE_OPTIONAL_HEADER structure, in the AddressOfEntryPoint)
   
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5000KB and 
      (all of them)
}  
