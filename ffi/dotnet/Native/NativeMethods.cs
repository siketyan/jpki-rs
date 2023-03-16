namespace Siketyan.Jpki.Native;

internal struct Card
{
}

internal struct CryptoAp
{
}

internal partial struct ByteArray
{
    public unsafe Span<byte> AsSpan()
    {
        return new Span<byte>(ptr, (int)len);
    }

    public static unsafe ByteArray FromSpan(Span<byte> span)
    {
        fixed (byte* ptr = &span.GetPinnableReference())
        {
            return new ByteArray
            {
                cap = (nuint)span.Length,
                len = (nuint)span.Length,
                ptr = ptr,
            };
        }
    }

    public static unsafe ByteArray FromSpan(ReadOnlySpan<byte> span)
    {
        fixed (byte* ptr = &span.GetPinnableReference())
        {
            return new ByteArray
            {
                cap = (nuint)span.Length,
                len = (nuint)span.Length,
                ptr = ptr,
            };
        }
    }
}
