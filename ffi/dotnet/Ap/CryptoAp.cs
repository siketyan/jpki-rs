using Siketyan.Jpki.Native;

namespace Siketyan.Jpki.Ap;

public class CryptoAp
{
    private readonly unsafe Native.CryptoAp* _ptr;
    private readonly Card _card;

    public CryptoAp(Card card)
    {
        _card = card;

        unsafe
        {
            _ptr = NativeMethods.jpki_new_crypto_ap(card.Ptr);
        }
    }

    ~CryptoAp()
    {
        unsafe
        {
            NativeMethods.jpki_crypto_ap_close(_ptr);
        }
    }

    public Span<byte> ReadCertificateSign(ReadOnlySpan<byte> pin, bool ca)
    {
        unsafe
        {
            fixed (byte* b = pin)
            {
                return NativeMethods.jpki_crypto_ap_read_certificate_sign(_ptr, b, ca).AsSpan();
            }
        }
    }

    public Span<byte> ReadCertificateAuth(bool ca)
    {
        unsafe
        {
            return NativeMethods.jpki_crypto_ap_read_certificate_auth(_ptr, ca).AsSpan();
        }
    }

    public Span<byte> Sign(ReadOnlySpan<byte> pin, ReadOnlySpan<byte> digest)
    {
        unsafe
        {
            fixed (byte* b = pin)
            {
                return NativeMethods.jpki_crypto_ap_sign(_ptr, b, ByteArray.FromSpan(digest)).AsSpan();
            }
        }
    }

    public Span<byte> Auth(ReadOnlySpan<byte> pin, ReadOnlySpan<byte> digest)
    {
        unsafe
        {
            fixed (byte* b = pin)
            {
                return NativeMethods.jpki_crypto_ap_auth(_ptr, b, ByteArray.FromSpan(digest)).AsSpan();
            }
        }
    }
}
