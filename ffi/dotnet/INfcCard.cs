namespace Siketyan.Jpki;

public interface INfcCard
{
    public Span<byte> Handle(ReadOnlySpan<byte> command);
}
