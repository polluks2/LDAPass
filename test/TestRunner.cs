using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace LDAPass.Test
{
    class TestRunner
    {
        static int port = 13389;
        static int passed = 0;
        static int failed = 0;

        static void Main()
        {
            var entries = new List<KeePassEntry>
            {
                new KeePassEntry {
                    Title = "Admin", UserName = "admin", Password = "secret123",
                    Url = "https://example.com", Notes = "test note", Group = "Websites"
                },
                new KeePassEntry {
                    Title = "Root", UserName = "root", Password = "toor",
                    Url = "", Notes = "", Group = "Servers"
                },
            };

            var db = new KeePassDb(() => entries);
            var server = new LdapServer(port, db);
            server.Start();

            try
            {
                Test("bind success", () => TestBind());
                Test("search all entries", () => TestSearch(entries.Count));
                Test("search by cn", () => TestSearchByCn("Admin"));
                Test("search by uid", () => TestSearchByUid("root"));
                Test("search with OR filter", () => TestSearchOr());
            }
            finally
            {
                server.Stop();
            }

            Console.WriteLine($"\n{passed}/{passed + failed} passed.");
            Environment.Exit(failed > 0 ? 1 : 0);
        }

        static void Test(string name, Action fn)
        {
            try
            {
                fn();
                Console.WriteLine($"  PASS  {name}");
                passed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  FAIL  {name}: {ex.Message}");
                failed++;
            }
        }

        static void TestBind()
        {
            var client = new TcpClient("127.0.0.1", port);
            using (var stream = client.GetStream())
            {
                SendBind(stream, 1);
                int rc = ReadBindResponse(stream);
                if (rc != 0)
                    throw new Exception($"bind failed: resultCode={rc}");
            }
        }

        static void TestSearch(int expectedCount)
        {
            var client = new TcpClient("127.0.0.1", port);
            using (var stream = client.GetStream())
            {
                SendBind(stream, 1);
                ReadBindResponse(stream);

                SendSearch(stream, 2, "(objectClass=*)", new[] { "*" });
                int count = ReadSearchResults(stream);
                if (count != expectedCount)
                    throw new Exception($"expected {expectedCount} entries, got {count}");
            }
        }

        static void TestSearchByCn(string title)
        {
            var client = new TcpClient("127.0.0.1", port);
            using (var stream = client.GetStream())
            {
                SendBind(stream, 1);
                ReadBindResponse(stream);
                SendSearch(stream, 2, $"(cn={title})", new[] { "cn", "uid" });
                int count = ReadSearchResults(stream);
                if (count != 1)
                    throw new Exception($"expected 1 entry for cn={title}, got {count}");
            }
        }

        static void TestSearchByUid(string uid)
        {
            var client = new TcpClient("127.0.0.1", port);
            using (var stream = client.GetStream())
            {
                SendBind(stream, 1);
                ReadBindResponse(stream);
                SendSearch(stream, 2, $"(uid={uid})", new[] { "uid" });
                int count = ReadSearchResults(stream);
                if (count != 1)
                    throw new Exception($"expected 1 entry for uid={uid}, got {count}");
            }
        }

        static void TestSearchOr()
        {
            var client = new TcpClient("127.0.0.1", port);
            using (var stream = client.GetStream())
            {
                SendBind(stream, 1);
                ReadBindResponse(stream);
                SendSearch(stream, 2, "(|(cn=Admin)(cn=Root))", new[] { "cn" });
                int count = ReadSearchResults(stream);
                if (count != 2)
                    throw new Exception($"expected 2 entries for OR filter, got {count}");
            }
        }

        static void SendBind(NetworkStream s, int msgId)
        {
            var bw = new BerWriter();
            bw.WriteTag(BerTag.Sequence);
            var content = new BerWriter();
            content.WriteInteger(msgId);
            content.WriteTag(BerTag.BindRequest);
            var bind = new BerWriter();
            bind.WriteInteger(3);
            bind.WriteOctetString("");
            bind.WriteTag(0x80);
            bind.WriteLength(0);
            var bindBytes = bind.ToArray();
            content.WriteLength(bindBytes.Length);
            content.WriteBytes(bindBytes);
            var msg = content.ToArray();
            bw.WriteLength(msg.Length);
            bw.WriteBytes(msg);
            var raw = bw.ToArray();
            s.Write(raw, 0, raw.Length);
        }

        static int ReadBindResponse(NetworkStream s)
        {
            int msgId = ReadMessage(s, out var protoOp, out byte[] content);
            if (protoOp != BerTag.BindResponse)
                throw new Exception($"expected BindResponse, got 0x{protoOp:X2}");
            var r = new BerReader(content);
            int rc = r.ReadEnumerated();
            return rc;
        }

        static void SendSearch(NetworkStream s, int msgId, string filterStr, string[] attrs)
        {
            var bw = new BerWriter();
            bw.WriteTag(BerTag.Sequence);
            var content = new BerWriter();
            content.WriteInteger(msgId);
            content.WriteTag(BerTag.SearchRequest);
            var search = new BerWriter();
            search.WriteOctetString("dc=keepass,dc=local");
            search.WriteEnumerated(2);
            search.WriteEnumerated(0);
            search.WriteInteger(0);
            search.WriteInteger(0);
            search.WriteBoolean(false);
            EncodeFilter(search, filterStr);
            search.WriteTag(BerTag.Sequence);
            var attrBytes = new BerWriter();
            foreach (var a in attrs)
                attrBytes.WriteOctetString(a);
            var attrData = attrBytes.ToArray();
            search.WriteLength(attrData.Length);
            search.WriteBytes(attrData);
            var searchBytes = search.ToArray();
            content.WriteLength(searchBytes.Length);
            content.WriteBytes(searchBytes);
            var msg = content.ToArray();
            bw.WriteLength(msg.Length);
            bw.WriteBytes(msg);
            s.Write(bw.ToArray(), 0, bw.Length);
        }

        static void EncodeFilter(BerWriter bw, string filter)
        {
            if (filter.StartsWith("(&") || filter.StartsWith("(|") || filter.StartsWith("(!"))
            {
                byte tag;
                if (filter[1] == '&') tag = BerTag.FilterAnd;
                else if (filter[1] == '|') tag = BerTag.FilterOr;
                else tag = BerTag.FilterNot;
                var children = new List<string>();
                int depth = 0;
                int childStart = -1;
                for (int i = 2; i < filter.Length; i++)
                {
                    if (filter[i] == '(')
                    {
                        if (depth == 0) childStart = i;
                        depth++;
                    }
                    else if (filter[i] == ')')
                    {
                        depth--;
                        if (depth == 0 && childStart >= 0)
                        {
                            children.Add(filter.Substring(childStart, i - childStart + 1));
                            childStart = -1;
                            if (filter[1] == '!' && children.Count == 1) break;
                        }
                    }
                }
                bw.WriteTag(tag);
                var buf = new BerWriter();
                foreach (var c in children)
                    EncodeFilter(buf, c);
                var b = buf.ToArray();
                bw.WriteLength(b.Length);
                bw.WriteBytes(b);
            }
            else if (filter.StartsWith("("))
            {
                int eq = filter.IndexOf('=');
                if (eq < 0) throw new Exception($"bad filter: {filter}");
                string attr = filter.Substring(1, eq - 1);
                string val = filter.Substring(eq + 1, filter.Length - eq - 2);
                if (val == "*")
                {
                    bw.WriteTag(BerTag.FilterPresent);
                    var raw = Encoding.UTF8.GetBytes(attr);
                    bw.WriteLength(raw.Length);
                    bw.WriteBytes(raw);
                }
                else
                {
                    bw.WriteTag(BerTag.FilterEqualityMatch);
                    var buf = new BerWriter();
                    buf.WriteOctetString(attr);
                    buf.WriteOctetString(val);
                    var b = buf.ToArray();
                    bw.WriteLength(b.Length);
                    bw.WriteBytes(b);
                }
            }
        }

        static int ReadSearchResults(NetworkStream s)
        {
            int count = 0;
            while (true)
            {
                int msgId = ReadMessage(s, out byte protoOp, out byte[] content);
                if (protoOp == BerTag.SearchResultEntry)
                {
                    count++;
                }
                else if (protoOp == BerTag.SearchResultDone)
                {
                    var r = new BerReader(content);
                    int rc = r.ReadEnumerated();
                    if (rc != 0)
                        throw new Exception($"search failed: resultCode={rc}");
                    return count;
                }
                else
                    throw new Exception($"unexpected op 0x{protoOp:X2}");
            }
        }

        static int ReadMessage(NetworkStream s, out byte protoOp, out byte[] content)
        {
            protoOp = 0;
            content = null;
            int b = s.ReadByte();
            if (b != 0x30) throw new Exception($"expected SEQUENCE, got 0x{b:X2}");
            int totalLen = ReadLength(s);
            byte[] data = ReadBytes(s, totalLen);
            var r = new BerReader(data);
            int msgId = r.ReadInteger();
            protoOp = r.ReadTag();
            int opLen = r.ReadLength();
            content = new byte[opLen];
            Array.Copy(data, r.Position, content, 0, opLen);
            return msgId;
        }

        static int ReadLength(NetworkStream s)
        {
            int b = s.ReadByte();
            if ((b & 0x80) == 0) return b;
            int cnt = b & 0x7F;
            int len = 0;
            for (int i = 0; i < cnt; i++)
                len = (len << 8) | s.ReadByte();
            return len;
        }

        static byte[] ReadBytes(NetworkStream s, int count)
        {
            byte[] buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = s.Read(buf, off, count - off);
                if (n <= 0) throw new EndOfStreamException();
                off += n;
            }
            return buf;
        }
    }
}
