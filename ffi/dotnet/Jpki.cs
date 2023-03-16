using Siketyan.Jpki.Native;

namespace Siketyan.Jpki;

public class Jpki
{
	static Jpki()
	{
		NativeMethods.jpki_init();
	}
}
