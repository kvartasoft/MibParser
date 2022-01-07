# MibParser
.NET Library for parsing SNMP MIB tables.

Contact us at www.kvarta.net for more!

Usage example:

```c#
using Kvartasoft.Snmp.MibParser;


MibParser mibParser = new MibParser();
mibParser.ParseMibFile("DVB-STREAM-MONITOR-021-MIB.mib");
var errors = mibParser.Errors;
var tables = mibParser.Tables;         
```
