using Loupe.Core.Sessions;

namespace Loupe.App.Services;

/// <summary>The one session store the whole app saves into and lists from.</summary>
public static class SessionService
{
    public static SessionStore Store { get; } = new();
}
