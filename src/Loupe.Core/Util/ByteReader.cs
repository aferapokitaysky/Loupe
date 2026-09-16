using System.Buffers.Binary;

namespace Loupe.Core.Util;

/// <summary>Bounds-checked big-endian reader over a packet buffer.</summary>
public ref struct ByteReader
{
    private readonly ReadOnlySpan<byte> _data;
    public int Position { get; private set; }

    public ByteReader(ReadOnlySpan<byte> data, int startOffset = 0)
    {
        _data = data;
        Position = startOffset;
    }

    public readonly int RemainingBytes => Math.Max(0, _data.Length - Position);
    public readonly bool HasAtLeast(int bytes) => RemainingBytes >= bytes;

    public byte ReadByte() => _data[Position++];

    public ushort ReadUInt16()
    {
        var value = BinaryPrimitives.ReadUInt16BigEndian(_data.Slice(Position, 2));
        Position += 2;
        return value;
    }

    public uint ReadUInt32()
    {
        var value = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(Position, 4));
        Position += 4;
        return value;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        var slice = _data.Slice(Position, count);
        Position += count;
        return slice;
    }

    public void Skip(int count) => Position += count;
}
