# Assets

`loupe.ico` belongs here - Windows needs a real icon file for the taskbar,
Explorer and the window chrome; the mark drawn in `Styles/Brand.xaml` covers
everything inside the UI itself.

Drop the file in and the build picks it up: `Loupe.App.csproj` sets
`<ApplicationIcon>Assets\loupe.ico</ApplicationIcon>` when it exists.
