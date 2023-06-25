using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

ConfigureService();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSaml2();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{Id?}");

app.Run();

void ConfigureService()
{
    builder.Services.AddRazorPages();
    builder.Services.Configure<Saml2Configuration>(builder.Configuration.GetSection("Saml2"));
    builder.Services.Configure<Saml2Configuration>(saml2Configuration =>
    {
        saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

        var entityDescriptor = new EntityDescriptor();
        entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(builder.Configuration["Saml2:IdMetaData"]));

        if (entityDescriptor.IdPSsoDescriptor != null)
        {
            saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
            saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);

        }
        else
        {
            throw new Exception("IdPSsoDescriptor not loaded from metadata.");
        }

    });

    builder.Services.AddSaml2();

}