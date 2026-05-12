using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LDAPass
{
    public static class BerTag
    {
        public const byte Boolean = 0x01;
        public const byte Integer = 0x02;
        public const byte OctetString = 0x04;
        public const byte Null = 0x05;
        public const byte Enumerated = 0x0A;
        public const byte Sequence = 0x30;
        public const byte Set = 0x31;

        public const byte BindRequest = 0x60;
        public const byte BindResponse = 0x61;
        public const byte UnbindRequest = 0x42;
        public const byte SearchRequest = 0x63;
        public const byte SearchResultEntry = 0x64;
        public const byte SearchResultDone = 0x65;
        public const byte SearchResultRef = 0x73;

        public const byte FilterAnd = 0xA0;
        public const byte FilterOr = 0xA1;
        public const byte FilterNot = 0xA2;
        public const byte FilterEqualityMatch = 0xA3;
        public const byte FilterSubstrings = 0xA4;
        public const byte FilterGreaterOrEqual = 0xA5;
        public const byte FilterLessOrEqual = 0xA6;
        public const byte FilterPresent = 0x87;
        public const byte FilterApproxMatch = 0xA8;
        public const byte FilterExtensibleMatch = 0xA9;
    }

    public class BerWriter
    {
        private readonly MemoryStream _buf = new MemoryStream();

        public void Clear()
        {
            _buf.SetLength(0);
        }

        public byte[] ToArray()
        {
            return _buf.ToArray();
        }

        public int Length => (int)_buf.Length;

        public void WriteByte(byte b)
        {
            _buf.WriteByte(b);
        }

        public void WriteBytes(byte[] data)
        {
            _buf.Write(data, 0, data.Length);
        }

        public void WriteTag(byte tag)
        {
            _buf.WriteByte(tag);
        }

        public void WriteLength(int length)
        {
            if (length < 0)
                throw new ArgumentException("Negative length");
            if (length < 128)
            {
                _buf.WriteByte((byte)length);
            }
            else
            {
                var bytes = new List<byte>();
                int tmp = length;
                while (tmp > 0)
                {
                    bytes.Insert(0, (byte)(tmp & 0xFF));
                    tmp >>= 8;
                }
                _buf.WriteByte((byte)(0x80 | bytes.Count));
                foreach (var b in bytes)
                    _buf.WriteByte(b);
            }
        }

        public void WriteInteger(int value)
        {
            _buf.WriteByte(BerTag.Integer);
            WriteLength(WriteIntegerRaw(value));
        }

        private int WriteIntegerRaw(int value)
        {
            long v = value;
            byte[] all8 = new byte[8];
            all8[0] = (byte)((ulong)v >> 56);
            all8[1] = (byte)((ulong)v >> 48);
            all8[2] = (byte)((ulong)v >> 40);
            all8[3] = (byte)((ulong)v >> 32);
            all8[4] = (byte)((ulong)v >> 24);
            all8[5] = (byte)((ulong)v >> 16);
            all8[6] = (byte)((ulong)v >> 8);
            all8[7] = (byte)v;

            int start = 0;
            if (value >= 0)
            {
                while (start < 7 && all8[start] == 0 && (all8[start + 1] & 0x80) == 0)
                    start++;
            }
            else
            {
                while (start < 7 && all8[start] == 0xFF && (all8[start + 1] & 0x80) != 0)
                    start++;
            }

            for (int i = start; i < 8; i++)
                _buf.WriteByte(all8[i]);
            return 8 - start;
        }

        public void WriteOctetString(string s)
        {
            var data = Encoding.UTF8.GetBytes(s ?? "");
            _buf.WriteByte(BerTag.OctetString);
            WriteLength(data.Length);
            _buf.Write(data, 0, data.Length);
        }

        public void WriteOctetStringRaw(byte[] data)
        {
            _buf.WriteByte(BerTag.OctetString);
            WriteLength(data.Length);
            _buf.Write(data, 0, data.Length);
        }

        public void WriteEnumerated(int value)
        {
            _buf.WriteByte(BerTag.Enumerated);
            WriteLength(WriteIntegerRaw(value));
        }

        public void WriteBoolean(bool value)
        {
            _buf.WriteByte(BerTag.Boolean);
            _buf.WriteByte(1);
            _buf.WriteByte(value ? (byte)0xFF : (byte)0x00);
        }

        public void WriteNull()
        {
            _buf.WriteByte(BerTag.Null);
            _buf.WriteByte(0);
        }

        public void WriteTagAndLength(byte tag, int length)
        {
            _buf.WriteByte(tag);
            WriteLength(length);
        }

    }

    public class BerReader
    {
        private readonly byte[] _data;
        private int _pos;

        public BerReader(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _pos = 0;
        }

        public int Position
        {
            get => _pos;
            set => _pos = value;
        }
        public bool HasData => _pos < _data.Length;

        public byte ReadTag()
        {
            if (_pos >= _data.Length)
                throw new EndOfStreamException();
            return _data[_pos++];
        }

        public int ReadLength()
        {
            if (_pos >= _data.Length)
                throw new EndOfStreamException();
            byte b = _data[_pos++];
            if ((b & 0x80) == 0)
                return b;
            int count = b & 0x7F;
            if (count == 0)
                throw new NotSupportedException("Indefinite length not supported");
            int length = 0;
            for (int i = 0; i < count; i++)
            {
                if (_pos >= _data.Length)
                    throw new EndOfStreamException();
                length = (length << 8) | _data[_pos++];
            }
            return length;
        }

        public int ReadInteger()
        {
            byte tag = ReadTag();
            if (tag != BerTag.Integer)
                throw new InvalidDataException($"Expected INTEGER tag 0x02, got 0x{tag:X2}");
            int len = ReadLength();
            if (_pos + len > _data.Length)
                throw new EndOfStreamException();
            int value;
            if (len == 0)
                value = 0;
            else
            {
                value = (sbyte)_data[_pos]; // sign-extend first byte
                for (int i = 1; i < len; i++)
                    value = (value << 8) | _data[_pos + i];
            }
            _pos += len;
            return value;
        }

        public int ReadEnumerated()
        {
            byte tag = ReadTag();
            if (tag != BerTag.Enumerated)
                throw new InvalidDataException($"Expected ENUMERATED tag 0x0A, got 0x{tag:X2}");
            int len = ReadLength();
            if (_pos + len > _data.Length)
                throw new EndOfStreamException();
            int value;
            if (len == 0)
                value = 0;
            else
            {
                value = (sbyte)_data[_pos];
                for (int i = 1; i < len; i++)
                    value = (value << 8) | _data[_pos + i];
            }
            _pos += len;
            return value;
        }

        public byte[] ReadOctetStringBytes()
        {
            byte tag = ReadTag();
            if (tag != BerTag.OctetString)
                throw new InvalidDataException($"Expected OCTET STRING tag 0x04, got 0x{tag:X2}");
            int len = ReadLength();
            if (_pos + len > _data.Length)
                throw new EndOfStreamException();
            byte[] result = new byte[len];
            Array.Copy(_data, _pos, result, 0, len);
            _pos += len;
            return result;
        }

        public string ReadOctetString()
        {
            return Encoding.UTF8.GetString(ReadOctetStringBytes());
        }

        public bool ReadBoolean()
        {
            byte tag = ReadTag();
            if (tag != BerTag.Boolean)
                throw new InvalidDataException($"Expected BOOLEAN tag 0x01, got 0x{tag:X2}");
            int len = ReadLength();
            if (len != 1)
                throw new InvalidDataException($"BOOLEAN length must be 1, got {len}");
            bool value = _data[_pos] != 0;
            _pos++;
            return value;
        }

        public void ReadNull()
        {
            byte tag = ReadTag();
            if (tag != BerTag.Null)
                throw new InvalidDataException($"Expected NULL tag 0x05, got 0x{tag:X2}");
            int len = ReadLength();
            if (len != 0)
                throw new InvalidDataException($"NULL length must be 0, got {len}");
        }

        public byte[] ReadContent()
        {
            int len = ReadLength();
            if (_pos + len > _data.Length)
                throw new EndOfStreamException();
            byte[] result = new byte[len];
            Array.Copy(_data, _pos, result, 0, len);
            _pos += len;
            return result;
        }

        public byte[] ReadTagAndContent()
        {
            byte tag = ReadTag(); // consume tag
            return ReadContent();
        }

        public byte[] ReadLdapMessage()
        {
            byte outerTag = ReadTag();
            if (outerTag != BerTag.Sequence)
                throw new InvalidDataException($"Expected SEQUENCE 0x30, got 0x{outerTag:X2}");
            return ReadContent();
        }
    }

}
