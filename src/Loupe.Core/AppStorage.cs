namespace Loupe.Core;

/// <summary>
/// Where Loupe keeps what it remembers: saved sessions, hide rules, favicons, the proxy's root
/// certificate and the language choice.
///
/// One place for the root so a rename of the app is a rename of one string - and so the move
/// from the old name carries the user's data with it instead of quietly stranding a folder of
/// saved sessions and an installed root certificate nobody can find any more.
/// </summary>
public static class AppStorage
{
    private const string FolderName = "Loupe";
    private const string PreviousFolderName = "NetSniffer";

    private static readonly Lazy<string> RootPath = new(Resolve);

    /// <summary>%LOCALAPPDATA%\Loupe. Created on first use.</summary>
    public static string Root => RootPath.Value;

    /// <summary>A file or folder inside the storage root.</summary>
    public static string PathTo(params string[] parts) =>
        Path.Combine([Root, .. parts]);

    private static string Resolve() =>
        Resolve(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

    /// <summary>The real logic, with the base folder passed in so it can be tested.</summary>
    internal static string Resolve(string localAppData)
    {
        string root = Path.Combine(localAppData, FolderName);
        string previous = Path.Combine(localAppData, PreviousFolderName);

        try
        {
            // Move, not copy: the old name is gone, and a copy would leave two diverging sets of
            // sessions. Only when there is nothing at the new path - never overwrite real data.
            if (!Directory.Exists(root) && Directory.Exists(previous))
                Directory.Move(previous, root);

            Directory.CreateDirectory(root);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Nothing here is worth failing startup over; the individual stores each handle a
            // directory they cannot write to.
        }

        return root;
    }
}
