using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace Kvartasoft.Snmp.MibParser
{

    public enum SnmpItemType
    {
        Group = 0,
        Item = 1,
        Table = 2,
        TableRowEntry = 3,
        TableColumn = 4,
        TrapType = 5,             

        TableRowEntrySyntax = 100,  // NOT ADDED IN TABLE
        TextConvention = 101,       // NOT ADDED IN TABLE
        TypeDefinition = 102,       // NOT ADDED IN TABLE
        Discard = 103               // NOT ADDED IN TABLE
    }
    public enum SnmpValueType
    {
        String = 0,
        Integer = 1/*,
        UnsignedInteger = 2,
        Float = 3*/
    }

    public class SnmpCustomType
    {
        public string Name { get; set; }
        public SnmpValueType ValueType { get; set; }
        public Dictionary<int, string> Items { get; set; }

        public SnmpCustomType()
        {
            Name = "";
            Items = new Dictionary<int, string>();
        }

        // Return true if end of list
        public bool AddValue(string value)
        {
            char[] separators = new char[] { '(', ')'};
            string[] elements = value.Split(separators);
            if (elements.Length == 3)
            {
                if (int.TryParse(elements[1], out var valueLong))
                    Items.Add(valueLong, elements[0]);

                if (elements[2].Length>0) // END OF LIST 
                {
                    if (elements[2] == "}")
                        return true;
                }
            }
            return false;
        }
    }

    public class SnmpItem
    {
        public SnmpItemType ItemType { get; set; }
        public SnmpValueType ValueType { get; set; }
        public SnmpCustomType CustomType { get; set; }
        public string Group { get; set; }
        public string Name { get; set; }
        public string? OID { get; set; }
        public string Description { get; set; }
        [JsonIgnore]
        public string MIB { get; set; }

        public SnmpItem(string name)
        {
            CustomType = new SnmpCustomType();
            Description = "";
            MIB = "";
            Group = "";
            group_oid_index = "";
            
            Name = name;
        }

		// used only when group accours before it has been defined in order to fix the OID it is private to avoid json serialization
        private string group_oid_index { get; set; } 
        public string GetGroupOidIndex()
        {
            return group_oid_index;
        }
        public void SetGroupOidIndex(string value)
        {
            group_oid_index = value;
        }
    }
    public enum DecodingState
    {
        NOT_SET,
        DEFINITIONS_BEGIN,
        IMPORTS,
        EXPORTS,
        ITEM_NAME,
        ITEM_TYPE,
        ITEM_INFO,
        ITEM_INFO_DESCRIPTION,
        ITEM_GROUP_START,
        ITEM_GROUP_NAME,
        ITEM_GROUP_INDEX,
        ITEM_GROUP_END,
        ITEM_TYPE_DEFINITION,
        ITEM_TYPE_INTEGER,
        ITEM_TYPE_INTEGER_LIST,
        DEFINITIONS_END,
        MACRO_BEGIN,
        MACRO_END
    }
    public class MibImports
    {
        public string From;
        public List<string> Items;

        public MibImports()
        {
            From = "";
            Items = new List<string>();
        }
    }
    public class MibParserError
    {
        public int LineIndex { get; set; }
        public string ErrorMessage { get; set; }

        public MibParserError(int line,string msg)
        {
            LineIndex = line;
            ErrorMessage = msg;
        }
    }
    public class MibParser
    {
        /// <summary>
        /// Public variables MIB table read
        /// </summary>
        public List<MibParserError> Errors;
        public bool LogErrors;
        public Dictionary<string,MibTable> Tables;


        /// <summary>
        /// Private variables used for decoding
        /// </summary>
        private DecodingState State;
        private DecodingState NextState;
        private string CurrentMIB;
        private SnmpItem CurrentItem;
        private SnmpCustomType? CurrentItemType;
        private int LineIndex; 
        private Dictionary<string, SnmpValueType> DefaultTypes;

        private void LoadImports()
        {
            // IMPORTS FINISHED!
            foreach (var import in Tables[CurrentMIB].Imports)
            {
                if (!Tables.ContainsKey(import.From))
                {
                    MibTable defaultTable = MibParser.ParseDefaultMIBs(import.From);
                    Tables.Add(import.From, defaultTable);
                }
            }
        }

        public static List<string> GetDefaultMibs()
        {
            var tmp = Assembly.GetExecutingAssembly().GetManifestResourceNames();
            List<string> list = new List<string>();
            foreach (var name in tmp)
            {
                list.Add(name.Remove(0, EmbeddedResourcePath.Length));
            }
            return list;
        }

        private void InitDefaultTypes()
        {
            DefaultTypes.Add("INTEGER", SnmpValueType.Integer);
            DefaultTypes.Add("REAL", SnmpValueType.Integer);
            DefaultTypes.Add("BOOLEAN", SnmpValueType.Integer);
            DefaultTypes.Add("BITS", SnmpValueType.Integer);
            DefaultTypes.Add("OCTET", SnmpValueType.String);
            DefaultTypes.Add("IpAddress", SnmpValueType.String);
            DefaultTypes.Add("Counter", SnmpValueType.Integer);
            DefaultTypes.Add("Gauge", SnmpValueType.Integer);
            DefaultTypes.Add("TimeTicks", SnmpValueType.Integer);
            DefaultTypes.Add("Opaque", SnmpValueType.String);
            DefaultTypes.Add("Counter32", SnmpValueType.Integer);
            DefaultTypes.Add("Gauge32", SnmpValueType.Integer);
            DefaultTypes.Add("Unsigned32", SnmpValueType.Integer);
            DefaultTypes.Add("Integer32", SnmpValueType.Integer);
            DefaultTypes.Add("DisplayString", SnmpValueType.String);//SNMPv2-TC
            DefaultTypes.Add("PhysAddress", SnmpValueType.String);
            DefaultTypes.Add("MacAddress", SnmpValueType.String);
            DefaultTypes.Add("TruthValue", SnmpValueType.Integer);
            DefaultTypes.Add("TestAndIncr", SnmpValueType.Integer);
        }
        private void AddError(string msg)
        {
            if (LogErrors)
            {
                Errors.Add(new MibParserError(LineIndex, msg));
                //Console.WriteLine("MIBPARSER:{0} {1}", LineIndex, msg);
            }
        }

        private void ParseImports(string line)
        {
            char[] separators = new char[] {' ', ',' , '\t'};
            string[] elements = line.Split(separators);
            for(int i=0;i<elements.Length;i++)
            {
                elements[i] = elements[i].Trim();
                if (elements[i].StartsWith("--"))
                    return;
                if (elements[i] == ";")
                {
                    LoadImports();
                    State = DecodingState.ITEM_NAME;
                    return;
                }
                if (elements[i].Length>0)
                {    
                    if (elements[i] == "FROM")
                    {
                        if (i + 1 < elements.Length)
                        {
                            Tables[CurrentMIB].AddImportFrom(elements[i + 1]);
                            if (elements[i+1].EndsWith(";"))
                            {
                                State = DecodingState.ITEM_NAME;
                                LoadImports();
                            }
                        }
                        return;
                                
                    }
                    else
                    {
                        Tables[CurrentMIB].AddImportItem(elements[i]);
                    }
                }
            }
            return;
        }
        // if return true discard rest of line
        private bool ParseSyntax(List<string> elements,string line)
        {
            if (elements.Count > 0)
            {
                if (elements.Count > 2)
                    if ((elements[0] == "SEQUENCE")
                        && (elements[1] == "OF"))
                    {
                        CurrentItem.ItemType = SnmpItemType.Table;
                        //CurrentItem.TableRowEntry = elements[2];
                        Tables[CurrentMIB].TableRowSyntax.Add(CurrentItem.Name, elements[2]); // CONNECT TABLE ROW ENTRY WITH GROUP
                        return true;
                    }
                if (elements.Count > 1)
                {
                    if ((elements[0] == "OCTET")
                        && (elements[1] == "STRING"))
                    {
                        CurrentItem.ValueType = SnmpValueType.String;
                        return true;
                    }
                    if ((elements[0] == "OBJECT")
                        && (elements[1] == "IDENTIFIER"))
                    {
                        CurrentItem.ValueType = SnmpValueType.String;
                        return true;
                    }
                }
                if (DefaultTypes.ContainsKey(elements[0]))
                {
                    CurrentItem.ValueType = DefaultTypes[elements[0]];
                    if (CurrentItem.ValueType == SnmpValueType.Integer)
                    {
                        if ((CurrentItem.ItemType == SnmpItemType.TextConvention) || (CurrentItemType != null))
                        {
                            CurrentItemType = new SnmpCustomType();
                            CurrentItemType.Name = CurrentItem.Name;
                            CurrentItemType.ValueType = SnmpValueType.Integer;
                            NextState = DecodingState.ITEM_NAME;
                        }
                        else
                            NextState = DecodingState.ITEM_INFO;
                        State = DecodingState.ITEM_TYPE_INTEGER;
                        return false; // DO NOT DISCARD REST OF LINE
                    }
                    return true; // discard rest of line
                }
                if (CurrentItem.ItemType == SnmpItemType.TextConvention) // Text convention syntax not found skip rest of line
                {
                    // Discard the rest....
                    State = DecodingState.ITEM_NAME;
                    return true;
                }

                if (Tables[CurrentMIB].CustomTypes.ContainsKey(elements[0]))
                {
                    CurrentItem.CustomType = Tables[CurrentMIB].CustomTypes[elements[0]];
                    CurrentItem.ValueType = CurrentItem.CustomType.ValueType;
                    // CUSTOM TYPE
                }
                else
                {
                    CurrentItem.ItemType = SnmpItemType.TableRowEntry;
                    // CONNECT TABLE ROW ENTRY WITH GROUP NOT NEEDED
                    //Table.TableRowGroup.Add(CurrentItem.Name, elements[0]); 
                }
            }
            return true;
        }

        private bool SetOID(string element)
        {
            if (int.TryParse(element, out var index))
            {
                string? group_oid = Tables[CurrentMIB].GetOid(CurrentItem.Group);
                // Use index to calculate OID!!!!

                if (group_oid == null)
                {
                    AddError("Group OID not found : " + CurrentItem.Group);
                    CurrentItem.OID = null;
                    CurrentItem.SetGroupOidIndex(index.ToString());
                }
                else
                    CurrentItem.OID = group_oid + '.' + index.ToString();
                State = DecodingState.ITEM_GROUP_END;
                return true;
            }
            return false;
        }

        private void ItemFinished()
        {
            CurrentItem.MIB = CurrentMIB;
            Tables[CurrentMIB].AddItem(CurrentItem);
            State = DecodingState.ITEM_NAME;
        }
        private void ParseItemLine(List<string> elements,string line)
        {
            for(int i=0;i<elements.Count;i++)
            {
                switch (State)
                {
                    case DecodingState.ITEM_NAME:
                        CurrentItemType = null;
                        CurrentItem = new SnmpItem(elements[i]);
                        if ((elements[i] == "ifType"))
                        {
                            int pes = 1;
                            pes++;
                        }
                        State = DecodingState.ITEM_TYPE;
                        break;
                    case DecodingState.ITEM_TYPE_DEFINITION:
                        if (elements[i] == "TEXTUAL-CONVENTION")
                        {
                            // Discard it....
                            CurrentItem.ItemType = SnmpItemType.TextConvention;
                            State = DecodingState.ITEM_INFO;
                        }
                        else
                        if (elements[i] == "SEQUENCE")
                        {
                            // Discard it.... TableRowEntry not needed.....
                            CurrentItem.ItemType = SnmpItemType.TableRowEntrySyntax;
                            State = DecodingState.ITEM_GROUP_END;
                        } else
                        {
                            if (elements[i] == "INTEGER")
                            {
                                CurrentItemType = new SnmpCustomType();
                                CurrentItemType.Name = CurrentItem.Name;
                                CurrentItemType.ValueType = SnmpValueType.Integer;
                                State = DecodingState.ITEM_TYPE_INTEGER;
                                NextState = DecodingState.ITEM_NAME;
                                CurrentItem.ItemType = SnmpItemType.TypeDefinition;
                            } else
                            if( (elements[i] == "OCTET")&&(i+1<elements.Count)&&(elements[i+1] == "STRING"))
                            {
                                CurrentItemType = new SnmpCustomType();
                                CurrentItemType.Name = CurrentItem.Name;
                                CurrentItem.ItemType = SnmpItemType.TypeDefinition;
                                CurrentItemType.ValueType = SnmpValueType.String;
                                State = DecodingState.ITEM_NAME;
                                Tables[CurrentMIB].CustomTypes.Add(CurrentItemType.Name, CurrentItemType);
                                return; // skip rest of line
                            }
                            else
                            {
                                // TODO DECODE ИЗБРОЕН ТИП
                                State = DecodingState.ITEM_GROUP_END;
                            }
                        }
                        break;
                    case DecodingState.ITEM_TYPE_INTEGER:
                        if (elements[i].StartsWith("(") && elements[i].EndsWith(")"))  // for example INTEGER (1..10)
                        {
                            if (CurrentItemType != null)
                            {
                                Tables[CurrentMIB].CustomTypes.Add(CurrentItemType.Name, CurrentItemType);
                            }
                            State = NextState;
                        } else
                        if ((elements[i] == "{")||(elements[i].StartsWith("{")))
                        {
                            State = DecodingState.ITEM_TYPE_INTEGER_LIST; // izbroen tip     
                            CurrentItem.CustomType = new SnmpCustomType();

                            if (elements[i].Length > 1) // missing space after { 
                            {
                                elements[i] = elements[i].Replace("{", "");
                                i--;
                                continue;
                            }
                        } else
                        {
                            // Error 
                            if (CurrentItemType != null)
                            {
                                Tables[CurrentMIB].CustomTypes.Add(CurrentItemType.Name, CurrentItemType);
                            }
                            State = NextState;
                            i--; // GO BACK
                        }
                        break;
                    case DecodingState.ITEM_TYPE_INTEGER_LIST:
                        if (elements[i] == "}")
                        {
                            if (CurrentItemType != null)
                            {
                                Tables[CurrentMIB].CustomTypes.Add(CurrentItemType.Name, CurrentItemType);
                            }
                            State = NextState;
                        }
                        else
                        {
                            if (CurrentItemType != null)
                            {
                                // ADD to Named custom type
                                if (CurrentItemType.AddValue(elements[i]))
                                {
                                    Tables[CurrentMIB].CustomTypes.Add(CurrentItemType.Name, CurrentItemType);
                                    State = NextState;
                                }
                            }else
                            {
                                // Add to CurrentItem.CustomType
                                if (CurrentItem.CustomType.AddValue(elements[i]))
                                {
                                    State = NextState;
                                }
                            }
                        }
                        break;

                    case DecodingState.ITEM_TYPE:
                        if (elements[i] == "::=")
                        {
                            State = DecodingState.ITEM_TYPE_DEFINITION;
                        }else
                        if ((elements[i] == "OBJECT-IDENTITY") || (elements[i] == "MODULE-IDENTITY")||(elements[i] == "MODULE-COMPLIANCE"))
                        {
                            CurrentItem.ItemType = SnmpItemType.Group;
                            State = DecodingState.ITEM_INFO;
                        }
                        else
                        if ((elements[i] == "OBJECT") && (i + 1 < elements.Count)&& (elements[i + 1] == "IDENTIFIER"))
                        {
                            i++;
                            CurrentItem.ItemType = SnmpItemType.Group;
                            State = DecodingState.ITEM_INFO;
                        }else
                        if (elements[i] == "TEXTUAL-CONVENTION")
                        {
                            CurrentItem.ItemType = SnmpItemType.TextConvention;
                            State = DecodingState.ITEM_INFO;
                        }
                        else
                        if ((elements[i] == "TRAP-TYPE")||(elements[i] == "NOTIFICATION-TYPE"))
                        {
                            CurrentItem.ItemType = SnmpItemType.TrapType;
                            State = DecodingState.ITEM_INFO;
                        }else
                        if (elements[i] == "OBJECT-TYPE")
                        {
                            CurrentItem.ItemType = SnmpItemType.Item;
                            State = DecodingState.ITEM_INFO;
                        }else
                        if ((elements[i] == "OBJECT-GROUP") || (elements[i] == "NOTIFICATION-GROUP"))
                        {
                            CurrentItem.ItemType = SnmpItemType.Discard;
                            State = DecodingState.ITEM_INFO;
                        }else
                        if (elements[i] == "MACRO")
                        {
                            CurrentItem.ItemType = SnmpItemType.Discard;
                            State = DecodingState.MACRO_BEGIN;
                        }
                        else
                        {
                            AddError("Object type not found : " + elements[i]);
                            State = DecodingState.ITEM_INFO;
                        }
                        break;
                    case DecodingState.ITEM_INFO:
                        if (elements[i] == "SYNTAX")
                        {
                            if (i + 1 < elements.Count)
                            {
                                if (ParseSyntax(elements.GetRange(i + 1, elements.Count - (i + 1)), line))
                                {
                                    if (CurrentItem.ItemType == SnmpItemType.TextConvention) // DISCARD TEXTUAL-CONVENTION SYNTAX IS THE LAST IN TEXTUAL CONVENTION
                                        State = DecodingState.ITEM_NAME;
                                    return;
                                }else
                                {
                                    i++; // discard INTEGER word and continue decoding 
                                    break; // continue decoding line
                                }
                            }
                            return; // discard line after SYNTAX keyword
                        }
                        if ((elements[i] == "ENTERPRISE")&&(CurrentItem.ItemType == SnmpItemType.TrapType)) // only in TRAP-TYPE
                        {
                            if (i + 1 < elements.Count)
                            {
                                CurrentItem.Group = elements[i + 1];
                            }
                            return;
                        }
                        if (elements[i] == "DESCRIPTION")
                        {
                            State = DecodingState.ITEM_INFO_DESCRIPTION;
                        }
                        else
                        if (elements[i] == "::=")
                            State = DecodingState.ITEM_GROUP_START;
                        else
                        if (elements[i] == "::={") // missing space....
                            State = DecodingState.ITEM_GROUP_NAME;
                        /*  else
                              AddError("Expected ::=");*/
                        break;
                    case DecodingState.ITEM_INFO_DESCRIPTION:
                        CurrentItem.Description  += line;
                        if (CurrentItem.Description.EndsWith("\""))
                        {
                            State = DecodingState.ITEM_INFO;
                            CurrentItem.Description = CurrentItem.Description.Replace("\"", "");
                        }
                        return; //line added to description exit!
                    case DecodingState.ITEM_GROUP_START:
                        if (CurrentItem.ItemType == SnmpItemType.TrapType)
                        {
                            if (SetOID(elements[i]))
                            {
                                // TRAP DECLARATION FINISHED
                                ItemFinished();
                                return; // skip rest of line OID set
                            }
                        }
                        if (elements[i].StartsWith("{"))
                        {
                            State = DecodingState.ITEM_GROUP_NAME;
                            if (elements[i].Length>1) // { is next to content missing space...
                            {
                                elements[i] = elements[i].Replace("{", "");
                                i--;
                                continue;
                            }
                            
                        }
                        else
                        {
                            if (CurrentItem.ItemType != SnmpItemType.TrapType)
                                AddError("Expected '{'");
                            State = DecodingState.ITEM_NAME; // Discard rest
                        }
                        break;
                    case DecodingState.ITEM_GROUP_NAME:
                        CurrentItem.Group = elements[i];
                        State = DecodingState.ITEM_GROUP_INDEX;
                        break;
                    case DecodingState.ITEM_GROUP_INDEX:
                        bool endOfGroup = false;
                        if (elements[i].EndsWith("}"))
                        {
                            endOfGroup = true;
                            elements[i] = elements[i].Replace("}", "");
                        }
                        if (!SetOID(elements[i]))
                        {
                            if (i > 0)
                                if (elements[i-1] == "iso")
                                {
                                    CurrentItem.OID = ".1.3.6.1";
                                    State = DecodingState.ITEM_GROUP_END;
                                    i = elements.Count - 2;
                                    break;
                                }
                            AddError("Expected integer");
                        }
                        if (endOfGroup )
                        {
                            ItemFinished();
                        }
                        break;
                    case DecodingState.ITEM_GROUP_END:
                        if (elements[i] == "}")
                        {
                            ItemFinished();
                        }/*else
                            AddError("Expected '}'");*/
                        break;

                }
            }
            return;
        }

        private void ParseLine(string line)
        {
            List<string> elements = new List<string>();

            LineIndex++;

            line = line.Trim();
            if (line.StartsWith("--")||(line.Length == 0))
                return; // comment

            char[] separators = new char[] { ' ', ',', '\t' };
            string[] tmp = line.Split(separators);
            for (int i = 0; i < tmp.Length; i++)
            {
                tmp[i] = tmp[i].Trim();
                if (tmp[i].Length>0)
                {
                    if (tmp[i].StartsWith("--")) // if end of line comment discard it
                        break;
                    elements.Add(tmp[i]);
                }
            }
            
            switch (State)
            {
                case DecodingState.NOT_SET:
                    if (elements.Count >= 4)
                    {
                        if ((elements[1] == "DEFINITIONS")&&
                            (elements[2] == "::=")&&
                            (elements[3] == "BEGIN"))
                        {
                            Tables[CurrentMIB].Name = elements[0];
                            State = DecodingState.DEFINITIONS_BEGIN;
                            return;
                        }
                    }
                    break;
                case DecodingState.DEFINITIONS_BEGIN:
                    if (elements.Count > 0)
                    {
                        if (elements[0] == "IMPORTS")
                        {
                            State = DecodingState.IMPORTS;
                            return;
                        }
                        if (elements[0] == "EXPORTS")
                        {
                            State = DecodingState.EXPORTS;
                            return;
                        }

                        // No Imports or Exports directy go to decoding items
                        State = DecodingState.ITEM_NAME;
                        ParseItemLine(elements, line);
                    }
                    break;
                case DecodingState.IMPORTS:
                    ParseImports(line);
                    return;
                case DecodingState.EXPORTS:
                    foreach (var element in elements)
                    {
                        if (element.Contains(";")) // discard all exports
                        {
                            State = DecodingState.ITEM_NAME;
                            return;
                        }
                    }
                    break;
                case DecodingState.MACRO_BEGIN:
                    foreach (var element in elements)
                    {
                        if (element.Contains("END")) // discard all macro content
                        {
                            State = DecodingState.ITEM_NAME;
                            return;
                        }
                    }
                    break;
                case DecodingState.ITEM_NAME:
                case DecodingState.ITEM_TYPE:
                case DecodingState.ITEM_INFO:
                case DecodingState.ITEM_GROUP_START:
                case DecodingState.ITEM_GROUP_NAME:
                case DecodingState.ITEM_GROUP_INDEX:
                case DecodingState.ITEM_GROUP_END:
                case DecodingState.ITEM_INFO_DESCRIPTION:
                case DecodingState.ITEM_TYPE_DEFINITION:
                case DecodingState.ITEM_TYPE_INTEGER:
                case DecodingState.ITEM_TYPE_INTEGER_LIST:
                    ParseItemLine(elements, line);
                    return;
            }
            return;
        }

        public MibParser()
        {
            CurrentMIB = "";
            CurrentItem = new SnmpItem("empty");
            Errors = new List<MibParserError>();
            DefaultTypes = new Dictionary<string, SnmpValueType>();
            InitDefaultTypes();
            Tables = new Dictionary<string, MibTable>();
            LogErrors = true;
        }
        private void InitParsing(string MIB)
        {
            Errors = new List<MibParserError>();
            State = DecodingState.NOT_SET; // RESET STATE WHEN START OF DECODING
            LineIndex = 0;
            CurrentMIB = MIB;
            if (!Tables.ContainsKey(CurrentMIB))
            {
                Tables.Add(CurrentMIB, new MibTable(Tables));
            }else
            {
                Tables[CurrentMIB] = new MibTable(Tables); /// Create new table parse again....
            }
        }
        private const string EmbeddedResourcePath = "Kvartasoft.Snmp.MibParser.mibs.";
        //private readonly string[] DefaultMIBs = { "SNMPv2-SMI",  "RFC1155-SMI","RFC1213-MIB", "SNMPv2-MIB", "IF-MIB", "SNMPv2-CONF", "SNMPv2-TC" };
         
        public static MibTable ParseDefaultMIBs(string mib)
        {
            MibParser mibParser = new MibParser(); 

            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedResourcePath + mib); //com.stackoverflow.plugin.example.Foo.pdf

            mibParser.InitParsing(mib);
            if (stream != null)
            {  
                StreamReader sr = new StreamReader(stream);
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    mibParser.ParseLine(line);
                }
                stream.Close();
            }
            //Console.WriteLine("File: {0} Errors:{1} ", mib, mibParser.Errors.Count);
            mibParser.FinishDecode();
            return mibParser.Tables[mib];
// USED TO EXPORT to JSON            ExportLookup("RFC1213-MIB", "ifOperStatus", "export.json");
        }

        public void ExportLookup(string table,string itemName,string file)
        {
            if (Tables.ContainsKey(table))
            {
                if (Tables[table].Items.ContainsKey(itemName))
                {
                    var item = Tables[table].Items[itemName];
                    if ((item.CustomType != null) && (item.CustomType.Items != null))
                    {
                        var customTypeItems = Tables[table].Items[itemName].CustomType.Items;
                        string json  = JsonConvert.SerializeObject(customTypeItems,Formatting.Indented);
                        File.WriteAllText(file, json);
                    }
                }
            }
                
        }

        public void ParseMibFile(string filename)
        {
            string? line;

            FileInfo fi = new FileInfo(filename);
            if (fi.Exists)
            {
                InitParsing(Path.GetFileName(filename));
                if (File.Exists(filename))
                {
                    // Read the file line by line.  
                    StreamReader file = new StreamReader(filename);
                    while ((line = file.ReadLine()) != null)
                    {
                        ParseLine(line);
                    }
                    file.Close();
                }
                FinishDecode();
            }else
            {
                var defaultMibs = GetDefaultMibs();
                if (defaultMibs.Contains(filename))
                    ParseDefaultMIBs(filename);
            }
        }


        private void FinishDecode()
        {
            //Tables[CurrentMIB].FixOids();
            Tables[CurrentMIB].RemoveInvalid();
            Tables[CurrentMIB].SortGroups();
        }

        public void ParseMibString(string mibText,string mibName)
        {
            string? line;

            InitParsing(mibName);

            StringReader strReader = new StringReader(mibText);
            while ((line = strReader.ReadLine()) != null)
            {
                ParseLine(line);
            }
            FinishDecode();
        }
    }

}
