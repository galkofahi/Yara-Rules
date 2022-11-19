rule Detect_Bumblebee_iso_newHash
{
    meta:

        create_date = "2022-11-19"
        hash256 = "37b35ed3db1be683015b19afe04ea5428b42e79b78b0529472849c7f7e1cb1b9"
        source = "https://cutt.ly/TMHKfbQ"
        author = "@galkofahi"
        description = "Detect_Bumblebee_iso (.img)"
        reference = "https://cutt.ly/5MHZvsB"
     

strings:
       $cmd1 = "\\System32\\cmd.exe" ascii wide nocase
       $dll_file = "UkBuGFiaRxAAfl.dll" ascii wide
       $bat_scr = "xipgxkiunOBWqZ.bat" ascii wide
       $Identi_Header = "OSTA Compressed Unicode" ascii wide
      
       
condition:
       uint16(0) != 0x5a4d and (all of them )
}
