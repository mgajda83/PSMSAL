using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

public static class MsalCacheHelper
{
    private static readonly string CacheFileUsrName = "usr_cache.dat";
    private static readonly string CacheFileAppName = "app_cache.dat";
    private static readonly string CacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PSMSAL"
    );

    public static async Task EnableSerializationUsrAsync(ITokenCache tokenCache)
    {
        // Konfiguracja parametrów przechowywania pliku
        var storageProperties = new StorageCreationPropertiesBuilder(CacheFileUsrName, CacheDir)
            .WithMacKeyChain("PSMSAL.TokenCache", "MSALCache")
            .WithLinuxKeyring("com.psmsal.tokencache", "default", "MSALCache",
                new KeyValuePair<string, string>("Version", "1.0"),
                new KeyValuePair<string, string>("ProductGroup", "PSMSAL"))
            .Build();

        // Tworzenie helpera, który zajmie się szyfrowaniem na Windows/Mac/Linux
        var msalCacheHelper = await Microsoft.Identity.Client.Extensions.Msal.MsalCacheHelper.CreateAsync(storageProperties);

        // Powiązanie helpera z pamięcią podręczną MSAL
        msalCacheHelper.RegisterCache(tokenCache);
    }

    public static async Task EnableSerializationAppAsync(ITokenCache tokenCache)
    {
        // Konfiguracja parametrów przechowywania pliku
        var storageProperties = new StorageCreationPropertiesBuilder(CacheFileAppName, CacheDir)
            .WithMacKeyChain("PSMSAL.TokenCache", "MSALCache")
            .WithLinuxKeyring("com.psmsal.tokencache", "default", "MSALCache",
                new KeyValuePair<string, string>("Version", "1.0"),
                new KeyValuePair<string, string>("ProductGroup", "PSMSAL"))
            .Build();

        // Tworzenie helpera, który zajmie się szyfrowaniem na Windows/Mac/Linux
        var msalCacheHelper = await Microsoft.Identity.Client.Extensions.Msal.MsalCacheHelper.CreateAsync(storageProperties);

        // Powiązanie helpera z pamięcią podręczną MSAL
        msalCacheHelper.RegisterCache(tokenCache);
    }
}
