using Siketyan.Jpki.Native;

namespace Siketyan.Jpki;

public class NfcCardAdapter
{
    internal readonly unsafe NfcCard* Ptr;

    private readonly INfcCard _inner;

    public NfcCardAdapter(INfcCard inner)
    {
        _inner = inner;

        unsafe
        {
            Ptr = NativeMethods.jpki_new_nfc_card(Handle);
        }
    }

    private ByteArray Handle(ByteArray command)
    {
        return ByteArray.FromSpan(_inner.Handle(command.AsSpan()));
    }
}
