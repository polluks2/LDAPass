using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace LDAPass
{
    public class LdapServer
    {
        private readonly int _port;
        private readonly KeePassDb _db;
        private TcpListener _listener;
        private Thread _acceptThread;
        private volatile bool _running;
        private readonly List<LdapSession> _sessions = new List<LdapSession>();

        public LdapServer(int port, KeePassDb db)
        {
            _port = port;
            _db = db;
        }

        public bool Running => _running;

        public void Start()
        {
            if (_running) return;
            _running = true;
            _listener = new TcpListener(IPAddress.Any, _port);
            _listener.Start();
            _acceptThread = new Thread(AcceptLoop)
            {
                IsBackground = true,
                Name = "LDAPass Accept"
            };
            _acceptThread.Start();
        }

        public void Stop()
        {
            _running = false;
            try { _listener?.Stop(); } catch { }
            lock (_sessions)
            {
                foreach (var s in _sessions)
                    s.Close();
                _sessions.Clear();
            }
        }

        private void AcceptLoop()
        {
            while (_running)
            {
                try
                {
                    var client = _listener.AcceptTcpClient();
                    var session = new LdapSession(client, _db, RemoveSession);
                    lock (_sessions)
                        _sessions.Add(session);
                    session.Start();
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("LDAPass accept error: " + ex.Message);
                }
            }
        }

        private void RemoveSession(LdapSession session)
        {
            lock (_sessions)
                _sessions.Remove(session);
        }
    }

    public delegate void SessionClosed(LdapSession session);

    public class LdapSession
    {
        private readonly TcpClient _client;
        private readonly KeePassDb _db;
        private readonly SessionClosed _onClose;
        private Thread _handler;
        private NetworkStream _stream;

        private static readonly byte[] PasswordsDn = Encoding.UTF8.GetBytes("ou=passwords,dc=keepass,dc=local");

        public LdapSession(TcpClient client, KeePassDb db, SessionClosed onClose)
        {
            _client = client;
            _db = db;
            _onClose = onClose;
        }

        public void Start()
        {
            _handler = new Thread(Run)
            {
                IsBackground = true,
                Name = "LDAPass Session"
            };
            _handler.Start();
        }

        public void Close()
        {
            try { _stream?.Close(); } catch { }
            try { _client?.Close(); } catch { }
        }

        private void Run()
        {
            try
            {
                using (_stream = _client.GetStream())
                {
                    _stream.ReadTimeout = 30000;
                    while (_client.Connected)
                    {
                        var msgId = ReadLdapMessage(out byte protocolOp, out byte[] content);
                        if (msgId < 0) break;

                        switch (protocolOp)
                        {
                            case BerTag.BindRequest:
                                HandleBind(msgId, content);
                                break;
                            case BerTag.SearchRequest:
                                HandleSearch(msgId, content);
                                break;
                            case BerTag.UnbindRequest:
                                return;
                            default:
                                Console.Error.WriteLine($"LDAPass: unknown op 0x{protocolOp:X2}");
                                return;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("LDAPass session: " + ex.Message);
            }
            finally
            {
                _onClose?.Invoke(this);
            }
        }

        private int ReadLdapMessage(out byte protocolOp, out byte[] content)
        {
            protocolOp = 0;
            content = null;

            int b;
            try
            {
                b = _stream.ReadByte();
            }
            catch
            {
                return -1;
            }
            if (b < 0) return -1;

            if (b != 0x30) return -1;

            int totalLen = ReadLengthFromStream();
            if (totalLen < 0) return -1;

            byte[] msgData = new byte[totalLen];
            int read = 0;
            while (read < totalLen)
            {
                int n = _stream.Read(msgData, read, totalLen - read);
                if (n <= 0) return -1;
                read += n;
            }

            var reader = new BerReader(msgData);
            int msgId = reader.ReadInteger();
            protocolOp = reader.ReadTag();

            int opLen = reader.ReadLength();
            content = new byte[opLen];
            Array.Copy(msgData, reader.Position, content, 0, opLen);

            return msgId;
        }

        private int ReadLengthFromStream()
        {
            int b = _stream.ReadByte();
            if (b < 0) return -1;
            if ((b & 0x80) == 0) return b;

            int count = b & 0x7F;
            int length = 0;
            for (int i = 0; i < count; i++)
            {
                int c = _stream.ReadByte();
                if (c < 0) return -1;
                length = (length << 8) | c;
            }
            return length;
        }

        private void HandleBind(int msgId, byte[] content)
        {
            var reader = new BerReader(content);
            int version = reader.ReadInteger();
            string name = reader.ReadOctetString();

            byte authTag = reader.ReadTag();
            if (authTag == 0x80)
            {
                int authLen = reader.ReadLength();
                string pass = Encoding.UTF8.GetString(content, reader.Position, authLen);
            }
            else if (authTag == BerTag.Null)
            {
                reader.ReadNull();
            }

            int bindContentLen = MeasureBindResponse(0);
            var bw = new BerWriter();
            bw.WriteTag(BerTag.Sequence);
            int msgLen = MeasureInt(msgId) + 1 + LenLen(bindContentLen) + bindContentLen;
            bw.WriteLength(msgLen);
            bw.WriteInteger(msgId);
            bw.WriteTag(BerTag.BindResponse);
            bw.WriteLength(bindContentLen);
            bw.WriteEnumerated(0);
            bw.WriteOctetString("");
            bw.WriteOctetString("");

            var resp = bw.ToArray();
            _stream.Write(resp, 0, resp.Length);
            _stream.Flush();
        }

        private int MeasureBindResponse(int rc)
        {
            return MeasureInt(rc) + 2 + 2;
        }

        private int MeasureInt(int v)
        {
            if (v == 0) return 3;
            long lv = v;
            byte[] b = new byte[8];
            b[0] = (byte)((ulong)lv >> 56);
            b[1] = (byte)((ulong)lv >> 48);
            b[2] = (byte)((ulong)lv >> 40);
            b[3] = (byte)((ulong)lv >> 32);
            b[4] = (byte)((ulong)lv >> 24);
            b[5] = (byte)((ulong)lv >> 16);
            b[6] = (byte)((ulong)lv >> 8);
            b[7] = (byte)lv;
            int start = 0;
            if (v >= 0)
                while (start < 7 && b[start] == 0 && (b[start + 1] & 0x80) == 0) start++;
            else
                while (start < 7 && b[start] == 0xFF && (b[start + 1] & 0x80) != 0) start++;
            return 2 + (8 - start);
        }

        private void HandleSearch(int msgId, byte[] content)
        {
            var reader = new BerReader(content);
            string baseDn = reader.ReadOctetString();
            int scope = reader.ReadEnumerated();
            int deref = reader.ReadEnumerated();
            int sizeLimit = reader.ReadInteger();
            int timeLimit = reader.ReadInteger();
            bool typesOnly = reader.ReadBoolean();

            Console.Error.WriteLine(
                $"LDAPass search: base='{baseDn}' scope={scope} deref={deref} sizeLimit={sizeLimit} timeLimit={timeLimit} typesOnly={typesOnly}");

            byte filterTag = reader.ReadTag();
            int filterLen = reader.ReadLength();
            byte[] filterContent = new byte[filterLen];
            Array.Copy(content, reader.Position, filterContent, 0, filterLen);
            reader = new BerReader(content);
            reader.ReadOctetString(); // skip base
            reader.ReadEnumerated();  // skip scope
            reader.ReadEnumerated();  // skip deref
            reader.ReadInteger();     // skip sizeLimit
            reader.ReadInteger();     // skip timeLimit
            reader.ReadBoolean();     // skip typesOnly
            reader.ReadTag();         // filter tag
            reader.ReadLength();      // filter length

            var requestedAttrs = new List<string>();
            if (reader.Position < content.Length)
            {
                byte attrSeqTag = reader.ReadTag();
                if (attrSeqTag == BerTag.Sequence)
                {
                    int attrSeqLen = reader.ReadLength();
                    int end = reader.Position + attrSeqLen;
                    while (reader.Position < end)
                    {
                        requestedAttrs.Add(reader.ReadOctetString());
                    }
                }
            }

            var entries = _db.GetEntries();
            var matches = new List<KeePassEntry>();

            foreach (var entry in entries)
            {
                int consumed = 0;
                if (MatchFilter(entry, filterTag, filterContent, ref consumed))
                    matches.Add(entry);
            }

            foreach (var entry in matches)
            {
                SendSearchResultEntry(msgId, entry, requestedAttrs);
            }

            SendSearchResultDone(msgId, 0);
        }

        private bool MatchFilter(KeePassEntry entry, byte tag, byte[] content, ref int consumed)
        {
            switch (tag)
            {
                case BerTag.FilterPresent:
                {
                    string attr = Encoding.UTF8.GetString(content);
                    consumed = content.Length;
                    return AttributeExists(entry, attr);
                }
                case BerTag.FilterEqualityMatch:
                {
                    var reader = new BerReader(content);
                    string attr = reader.ReadOctetString();
                    string val = reader.ReadOctetString();
                    consumed = reader.Position;
                    return AttributeMatches(entry, attr, val);
                }
                case BerTag.FilterAnd:
                {
                    var reader = new BerReader(content);
                    while (reader.Position < content.Length)
                    {
                        byte subTag = reader.ReadTag();
                        int subLen = reader.ReadLength();
                        byte[] subContent = GetSubContent(content, reader.Position, subLen);
                        int subConsumed = 0;
                        if (!MatchFilter(entry, subTag, subContent, ref subConsumed))
                        {
                            consumed = content.Length;
                            return false;
                        }
                        reader.Position += subLen;
                    }
                    consumed = content.Length;
                    return true;
                }
                case BerTag.FilterOr:
                {
                    var reader = new BerReader(content);
                    while (reader.Position < content.Length)
                    {
                        byte subTag = reader.ReadTag();
                        int subLen = reader.ReadLength();
                        byte[] subContent = GetSubContent(content, reader.Position, subLen);
                        int subConsumed = 0;
                        if (MatchFilter(entry, subTag, subContent, ref subConsumed))
                        {
                            consumed = content.Length;
                            return true;
                        }
                        reader.Position += subLen;
                    }
                    consumed = content.Length;
                    return false;
                }
                case BerTag.FilterNot:
                {
                    var reader = new BerReader(content);
                    byte subTag = reader.ReadTag();
                    int subLen = reader.ReadLength();
                    byte[] subContent = GetSubContent(content, reader.Position, subLen);
                    int subConsumed = 0;
                    bool result = MatchFilter(entry, subTag, subContent, ref subConsumed);
                    consumed = content.Length;
                    return !result;
                }
                default:
                    consumed = content.Length;
                    return true;
            }
        }

        private byte[] GetSubContent(byte[] data, int offset, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(data, offset, result, 0, length);
            return result;
        }

        private bool AttributeExists(KeePassEntry entry, string attr)
        {
            if (attr.Equals("objectClass", StringComparison.OrdinalIgnoreCase)) return true;
            if (attr.Equals("cn", StringComparison.OrdinalIgnoreCase)) return true;
            if (attr.Equals("sn", StringComparison.OrdinalIgnoreCase)) return !string.IsNullOrEmpty(entry.Title);
            if (attr.Equals("uid", StringComparison.OrdinalIgnoreCase)) return !string.IsNullOrEmpty(entry.UserName);
            if (attr.Equals("mail", StringComparison.OrdinalIgnoreCase))
                return entry.Url.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("telephoneNumber", StringComparison.OrdinalIgnoreCase))
                return entry.Url.StartsWith("tel:", StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("userPassword", StringComparison.OrdinalIgnoreCase)) return !string.IsNullOrEmpty(entry.Password);
            if (attr.Equals("description", StringComparison.OrdinalIgnoreCase)) return !string.IsNullOrEmpty(entry.Notes);
            if (attr.Equals("url", StringComparison.OrdinalIgnoreCase)) return !string.IsNullOrEmpty(entry.Url);
            if (attr.Equals("ou", StringComparison.OrdinalIgnoreCase)) return true;
            return entry.CustomFields.ContainsKey(attr);
        }

        private bool AttributeMatches(KeePassEntry entry, string attr, string val)
        {
            if (attr.Equals("objectClass", StringComparison.OrdinalIgnoreCase))
            {
                return val.Equals("top", StringComparison.OrdinalIgnoreCase)
                    || val.Equals("person", StringComparison.OrdinalIgnoreCase)
                    || val.Equals("organizationalPerson", StringComparison.OrdinalIgnoreCase)
                    || val.Equals("inetOrgPerson", StringComparison.OrdinalIgnoreCase);
            }
            if (attr.Equals("cn", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.Title, val, StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("sn", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.Title, val, StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("uid", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.UserName, val, StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("userPassword", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.Password, val, StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("mail", StringComparison.OrdinalIgnoreCase))
            {
                var mail = StripPrefix(entry.Url, "mailto:");
                return mail != null && string.Equals(mail, val, StringComparison.OrdinalIgnoreCase);
            }
            if (attr.Equals("telephoneNumber", StringComparison.OrdinalIgnoreCase))
            {
                var tel = StripPrefix(entry.Url, "tel:");
                return tel != null && string.Equals(tel, val, StringComparison.OrdinalIgnoreCase);
            }
            if (attr.Equals("description", StringComparison.OrdinalIgnoreCase))
                return entry.Notes != null && entry.Notes.IndexOf(val, StringComparison.OrdinalIgnoreCase) >= 0;
            if (attr.Equals("url", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.Url, val, StringComparison.OrdinalIgnoreCase);
            if (attr.Equals("ou", StringComparison.OrdinalIgnoreCase))
                return string.Equals(entry.Group, val, StringComparison.OrdinalIgnoreCase);
            if (entry.CustomFields.TryGetValue(attr, out string cv))
                return string.Equals(cv, val, StringComparison.OrdinalIgnoreCase);
            return false;
        }

        private void SendSearchResultEntry(int msgId, KeePassEntry entry, List<string> requestedAttrs)
        {
            var title = string.IsNullOrEmpty(entry.Title) ? "unnamed" : entry.Title;
            var dnBytes = Encoding.UTF8.GetBytes($"cn={EncodeDnValue(title)},{Encoding.UTF8.GetString(PasswordsDn)}");
            var attrData = BuildAttributes(entry, requestedAttrs);

            var entryContent = new BerWriter();
            entryContent.WriteOctetStringRaw(dnBytes);
            entryContent.WriteTag(BerTag.Sequence);
            entryContent.WriteLength(attrData.Length);
            entryContent.WriteBytes(attrData);
            byte[] entryContentBytes = entryContent.ToArray();

            var bw = new BerWriter();
            bw.WriteTag(BerTag.Sequence);
            int sreTotalLen = 1 + LenLen(entryContentBytes.Length) + entryContentBytes.Length;
            int msgContentLen = MeasureInt(msgId) + sreTotalLen;
            bw.WriteLength(msgContentLen);
            bw.WriteInteger(msgId);
            bw.WriteTag(BerTag.SearchResultEntry);
            bw.WriteLength(entryContentBytes.Length);
            bw.WriteBytes(entryContentBytes);

            var data = bw.ToArray();
            _stream.Write(data, 0, data.Length);
            _stream.Flush();
        }

        private int LenLen(int len)
        {
            if (len < 128) return 1;
            int cnt = 0;
            int tmp = len;
            while (tmp > 0) { cnt++; tmp >>= 8; }
            return 1 + cnt;
        }

        private byte[] BuildAttributes(KeePassEntry entry, List<string> requestedAttrs)
        {
            bool allAttrs = requestedAttrs.Count == 0
                || (requestedAttrs.Count == 1 && requestedAttrs[0].Equals("*", StringComparison.Ordinal));

            var bw = new BerWriter();

            void AddAttr(string name, string value)
            {
                if (string.IsNullOrEmpty(value)) return;
                if (!allAttrs && !requestedAttrs.Contains(name) && !requestedAttrs.Contains("*"))
                    return;
                var valBytes = Encoding.UTF8.GetBytes(value ?? "");
                var nameBytes = Encoding.UTF8.GetBytes(name);
                bw.WriteTag(BerTag.Sequence);
                int attrLen = 2 + nameBytes.Length + 2 + 2 + valBytes.Length;
                bw.WriteLength(attrLen);
                bw.WriteOctetStringRaw(nameBytes);
                bw.WriteTag(BerTag.Set);
                bw.WriteLength(2 + valBytes.Length);
                bw.WriteOctetStringRaw(valBytes);
            }

            if (allAttrs || requestedAttrs.Contains("objectClass"))
            {
                var names = new[] { "top", "person", "organizationalPerson", "inetOrgPerson" };
                var nameBytes = Encoding.UTF8.GetBytes("objectClass");
                var valBytesList = new List<byte>();
                foreach (var n in names)
                {
                    var vb = Encoding.UTF8.GetBytes(n);
                    valBytesList.AddRange(new byte[] { BerTag.OctetString });
                    valBytesList.AddRange(EncodeLen(vb.Length));
                    valBytesList.AddRange(vb);
                }
                bw.WriteTag(BerTag.Sequence);
                int attrLen = 2 + nameBytes.Length + 2 + valBytesList.Count;
                bw.WriteLength(attrLen);
                bw.WriteOctetStringRaw(nameBytes);
                bw.WriteTag(BerTag.Set);
                bw.WriteLength(valBytesList.Count);
                bw.WriteBytes(valBytesList.ToArray());
            }

            AddAttr("cn", entry.Title);
            AddAttr("sn", entry.Title);
            AddAttr("uid", entry.UserName);
            AddAttr("userPassword", entry.Password);
            AddAttr("description", entry.Notes);
            AddAttr("url", entry.Url);

            var mail = StripPrefix(entry.Url, "mailto:");
            if (mail != null) AddAttr("mail", mail);

            var tel = StripPrefix(entry.Url, "tel:");
            if (tel != null) AddAttr("telephoneNumber", tel);

            if (!string.IsNullOrEmpty(entry.Group))
            {
                AddAttr("ou", entry.Group);
            }

            foreach (var kv in entry.CustomFields)
            {
                if (allAttrs || requestedAttrs.Contains(kv.Key))
                {
                    AddAttr(kv.Key, kv.Value);
                }
            }

            return bw.ToArray();
        }

        private byte[] EncodeLen(int len)
        {
            if (len < 128)
                return new byte[] { (byte)len };
            var bytes = new List<byte>();
            int tmp = len;
            while (tmp > 0)
            {
                bytes.Insert(0, (byte)(tmp & 0xFF));
                tmp >>= 8;
            }
            bytes.Insert(0, (byte)(0x80 | bytes.Count));
            return bytes.ToArray();
        }

        private void SendSearchResultDone(int msgId, int resultCode)
        {
            int doneContentLen = MeasureLdapResult(resultCode);
            var bw = new BerWriter();
            bw.WriteTag(BerTag.Sequence);
            int totalLen = MeasureInt(msgId) + 1 + LenLen(doneContentLen) + doneContentLen;
            bw.WriteLength(totalLen);
            bw.WriteInteger(msgId);
            bw.WriteTag(BerTag.SearchResultDone);
            bw.WriteLength(doneContentLen);
            bw.WriteEnumerated(resultCode);
            bw.WriteOctetString("");
            bw.WriteOctetString("");

            var data = bw.ToArray();
            _stream.Write(data, 0, data.Length);
            _stream.Flush();
        }

        private int MeasureLdapResult(int rc)
        {
            return MeasureInt(rc) + 2 + 2;
        }

        private string EncodeDnValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(",") || value.Contains("=") || value.Contains("+") || value.Contains("\"") || value.Contains("\\") || value.Contains("<") || value.Contains(">") || value.Contains(";") || value.Contains("#"))
            {
                return $"\\{value}";
            }
            return value;
        }

        private static string StripPrefix(string url, string prefix)
        {
            if (string.IsNullOrEmpty(url)) return null;
            if (url.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return url.Substring(prefix.Length);
            return null;
        }
    }

    public class KeePassEntry
    {
        public string Title { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Url { get; set; }
        public string Notes { get; set; }
        public string Group { get; set; }
        public Dictionary<string, string> CustomFields { get; } = new Dictionary<string, string>();
    }

    public class KeePassDb
    {
        private readonly Func<List<KeePassEntry>> _entryProvider;

        public KeePassDb(Func<List<KeePassEntry>> entryProvider)
        {
            _entryProvider = entryProvider ?? throw new ArgumentNullException(nameof(entryProvider));
        }

        public List<KeePassEntry> GetEntries()
        {
            return _entryProvider();
        }
    }
}
