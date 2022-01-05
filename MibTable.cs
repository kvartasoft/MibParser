using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;

namespace Kvartasoft.Snmp.MibParser
{
    public class MibTable
    {
        public string Name;
        public Dictionary<string, SnmpItem> Groups;
        public Dictionary<string, SnmpItem> Items;
        [JsonIgnore]
        public Dictionary<string, SnmpCustomType> CustomTypes;

        [JsonIgnore]
        public Dictionary<string, MibTable> AllTables;
        

        //               TableName SyntaxName
        public Dictionary<string, string> TableRowSyntax;

        public string? GetOid(string group)
        {
            SnmpItem? item = FindGroupInAllTables(group);
            if (item != null)
            {
                if (item.OID == null)
                {
                    string? oid = GetOid(item.Group); // recursively search for oid and fix it
                    if (oid != null)
                    {
                        item.OID = oid + '.' + item.GetGroupOidIndex();
                        return item.OID;
                    }
                    else
                        return null;
                }else
                {
                    return item.OID;
                }
            }
            return null;
        }


        public MibTable(Dictionary<string,MibTable> allDefaultTables)
        {
            Name = "";
            Groups = new Dictionary<string, SnmpItem>();
            Items = new Dictionary<string, SnmpItem>();
            Imports = new List<MibImports>();
            TableRowSyntax = new Dictionary<string, string>();
            //TableRowGroup = new Dictionary<string, string>(); // NOT NEEDED
            CustomTypes = new Dictionary<string, SnmpCustomType>();
            AllTables = allDefaultTables;



            // Default Enterprises group

            SnmpItem iso = new SnmpItem("iso");
            iso.ItemType = SnmpItemType.Group;
            iso.Group = "#";
            iso.OID = ".1";
            iso.MIB = "";
            Groups.Add(iso.Name, iso);

            //
            /*SnmpItem internet = new SnmpItem("iso.org.dod.internet");
            internet.ItemType = SnmpItemType.Group;
            internet.Group = "#";
            internet.OID = "1.3.6.1";
            Groups.Add(internet.Name, internet);*/

            /* SnmpItem privateGroup = new SnmpItem("private");
             privateGroup.ItemType = SnmpItemType.Group;
             privateGroup.Group = "iso.org.dod.internet";
             privateGroup.OID = "1.3.6.1.4";
             Groups.Add(privateGroup.Name, privateGroup);

             SnmpItem enterprises = new SnmpItem("enterprises");
             enterprises.ItemType = SnmpItemType.Group;
             enterprises.Group = "private";
             enterprises.OID = "1.3.6.1.4.1";
             Groups.Add(enterprises.Name, enterprises);*/
        }

        public void AddItem(SnmpItem item)
        {
            if (item.Group == null) // discard null group items
                return;
            // Set to Table Column if group is TableRowEntry
            if (Groups.ContainsKey(item.Group))
                if (Groups[item.Group].ItemType == SnmpItemType.TableRowEntry)
                 {
                    if (TableRowSyntax.ContainsValue(item.Name)) // Discard TableRowEntrfrom 
                        item.ItemType = SnmpItemType.TableRowEntrySyntax;
                    else
                        item.ItemType = SnmpItemType.TableColumn;
                }
                        
                    
           
            switch (item.ItemType)
            {
                // DO NOT ADD IT WE DO NOT NEED IT! ... case SnmpItemType.TableRowEntrySyntax:
                case SnmpItemType.TableRowEntry:
                case SnmpItemType.Group:
                case SnmpItemType.Table:
                    if (!Groups.ContainsKey(item.Name))
                        Groups.Add(item.Name, item); // WHAT WE DO IF ALREADY EXISTS!!!!?!!?!?!?!?
                    break;
                case SnmpItemType.Item:
                case SnmpItemType.TableColumn:
                case SnmpItemType.TrapType:
                    if (!Items.ContainsKey(item.Name)) // Do not add twice if we parse file twise otherwise should not happen to have two identical names!
                        Items.Add(item.Name, item);
                    break;
            }
        }

        private SnmpItem? FindGroupInAllTables(string groupName)
        {
            if (Groups.ContainsKey(groupName))
                return Groups[groupName];
            else // Not found in current table search in other tables
            {
                foreach(var t in AllTables.Values)
                {
                    if (t.Groups.ContainsKey(groupName))
                        return t.Groups[groupName];
                }
            }
            // NOT FOUND !!!  SHOULD NOT GET HERE
            return null;
        }

        private int AddGroup(Dictionary<string, SnmpItem> sortedGroups,SnmpItem? group,int i)
        {
            if (group != null)
                if (group.Group == "#")
                { 
                    if (!sortedGroups.ContainsKey(group.Name))
                        sortedGroups.Add(group.Name, group);
                }else
                {
                    if (sortedGroups.ContainsKey(group.Group))
                    {
                        if (!sortedGroups.ContainsKey(group.Name))
                            sortedGroups.Add(group.Name, group);
                    }
                    else
                    {
                        return AddGroup(sortedGroups, FindGroupInAllTables(group.Group),-1);
                    }
                }
            return i;
        }
        public void SortGroups()
        {
            Dictionary<string, SnmpItem> sortedGroups = new Dictionary<string, SnmpItem>();
            for (int i = 0; i < Groups.Count; i++)
            {
                var group = Groups.ElementAt(i).Value;
                if (group.OID != null) // discard groups with invalid oids
                {
                    i = AddGroup(sortedGroups, group, i);
                    //Console.WriteLine("{0} {1} {2}", i, group.Name, group.OID);
                }
            }
            Groups = sortedGroups;
        }

        public int GetOidsCount()
        {
            return Items.Count;
        }

        public void FixOids()
        {
            foreach (var groupDictionary in Groups)
            {
                var group = groupDictionary.Value;
                if (group.OID == null)
                {
                    group.OID = GetOid(groupDictionary.Key);
                }
            }
        }

        public void RemoveInvalid()
        {  
            for(int i=0;i<Groups.Count;i++)
            {
                var group = Groups.ElementAt(i);
                if (group.Value.Group != null)
                {
                    if (!Groups.ContainsKey(group.Value.Name))
                    {
                        // Remove groups with parent invalid!
                        Groups.Remove(group.Key);
                        i--;
                    }
                }
            }
            for (int i = 0; i < Items.Count; i++)
            {
                var item = Items.ElementAt(i);
                if (item.Value.Group != null)
                {
                    if (!Groups.ContainsKey(item.Value.Group))
                    {
                        // Remove item with parent invalid!
                        Items.Remove(item.Key);
                        i--;
                    }
                }
            }
        }

        #region Imports 
        [JsonIgnore]
        public List<MibImports> Imports; 
        public void AddImportItem(string item)
        {
            if (Imports.Count == 0)
                Imports.Add(new MibImports());
            Imports[Imports.Count - 1].Items.Add(item);
        }
        public void AddImportFrom(string from)
        {
            if (Imports.Count>0)
            {
                Imports[Imports.Count - 1].From = from;
                if (from.EndsWith(";"))
                {
                    // remove ";"
                    Imports[Imports.Count - 1].From = from.Remove(from.Length - 1, 1);
                }
                else
                {
                    Imports.Add(new MibImports());
                }
            }
        }
        #endregion
    }

}
