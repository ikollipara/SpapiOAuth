# Amazon Seller Profile API Authentication

This is a simple site that can be used to get the refresh token for a given Amazon Seller Profile.
It is a simple F# port of https://www.jesseevers.com/spapi-oauth/.


## Configuration
The application uses the dotnet standard `appsettings.json` for configuration.
Please set the following:
- `SPAPI_APP_ID`: Your Application ID
- `SPAPI_AUTH_CLIENT_ID`: Your LWA Client ID
- `SPAPI_AUTH_CLIENT_SECRET`: Your LWA Client Secret

On the amazon side, the callback url is `/redirect`.
