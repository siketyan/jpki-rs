using Siketyan.Jpki.Native;

namespace Siketyan.Jpki;

public class Card
{
    internal readonly unsafe Native.Card* Ptr;

    private readonly NfcCardAdapter _adapter;

    public Card(NfcCardAdapter adapter)
    {
        _adapter = adapter;

        unsafe
        {
            Ptr = NativeMethods.jpki_new_card(adapter.Ptr);
        }
    }

    public Ap.CryptoAp OpenCryptoAp()
    {
        return new Ap.CryptoAp(this);
    }
}
