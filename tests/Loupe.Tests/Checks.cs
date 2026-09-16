using System.Text;
public static class T
{
    public static int Pass, Fail;
    public static void Check(string name, bool ok, string? detail = null)
    {
        if (ok) { Pass++; Console.WriteLine($"  PASS  {name}"); }
        else { Fail++; Console.WriteLine($"  FAIL  {name}{(detail is null ? "" : "  -> " + detail)}"); }
    }
    public static void Eq<TV>(string name, TV expected, TV actual) =>
        Check(name, EqualityComparer<TV>.Default.Equals(expected, actual), $"expected [{expected}] got [{actual}]");
    public static void Section(string s) => Console.WriteLine($"\n== {s} ==");
}
