//----------------------------------------------------
// Name:    SpapiOAuth/Program.fs
// Author:  Ian Kollipara <ian.kollipara@gmail.com>
// Created: 2025-11-28
// Description:
//  A port of https://www.jesseevers.com/spapi-oauth/
//  into the dotnet world. Written in F#
//----------------------------------------------------

// Imports
open Falco
open Falco.Routing
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open Microsoft.Extensions.Configuration
open System.Net.Http
open System.Net.Http.Json

// Custom Types
type AmazonSellerAPITokenResponse = {
    refresh_token: string
    access_token: string
    expires_in: string
}

type AmazonSellerAPITokenErrorReponse = { error: string }

// Useful Named Constants
module Constants =
    [<Literal>]
    let SPAPI_STATE_SESSION_KEY = "spapi_auth_state"

    [<Literal>]
    let SPAPI_OAUTH_URL = "https://sellercentral.amazon.com"

    [<Literal>]
    let SPAPI_OAUTH_PATH = "/apps/authorize/consent"

    [<Literal>]
    let AMAZON_API_TOKEN_URL = "https://api.amazon.com/auth/o2/token"

type SpapiOAuth = class end

module Views =
    open Falco.Markup

    /// Authorization View
    let Authorize =
        _html [ _lang_ "en" ] [
            _head [] [ _title [] [ _text "Spapi OAuth" ] ]
            _body [] [ _form [ _methodPost_ ] [ _input [ _typeSubmit_; _value_ "Authorize" ] ] ]
        ]

    let Error (msg: string) =
        _html [ _lang_ "en" ] [
            _head [] [ _title [] [ _text "Something went wrong" ] ]
            _body [] [ _h1 [] [ _text "Uh Oh." ]; _p [] [ _text msg ] ]
        ]

    let Success (response: AmazonSellerAPITokenResponse) =
        _html [ _lang_ "en" ] [
            _head [] [ _title [] [ _text "Success" ] ]
            _body [] [
                _h1 [] [ _text "Success!" ]
                _p [] [ _text $"Refresh Token: {response.refresh_token}" ]
            ]
        ]



module Handlers =

    let AuthorizeGet: HttpHandler = Response.ofHtml Views.Authorize

    let AuthorizePost: HttpHandler =
        fun ctx ->
            let config = ctx.Plug<IConfiguration>()
            let logger = ctx.Plug<ILogger<SpapiOAuth>>()

            logger.LogInformation "Beginning Authorization Request..."
            let state = System.Guid.NewGuid()
            let appId = config.GetValue<string> "SPAPI_APP_ID"

            ctx.Session.Set(Constants.SPAPI_STATE_SESSION_KEY, state.ToByteArray())


            (Response.withHeaders [
                "Referrer-Policy", "no-referrer"
                "Location",
                $"{Constants.SPAPI_OAUTH_URL}{Constants.SPAPI_OAUTH_PATH}?state={state}&application_id={appId}"
             ]
             >> Response.withStatusCode 302
             >> Response.ofEmpty)
                ctx

    let RedirectGet: HttpHandler =
        fun ctx ->

            // Retrieve needed Dependencies
            let clientFactory = ctx.Plug<IHttpClientFactory>()
            let config = ctx.Plug<IConfiguration>()
            let logger = ctx.Plug<ILogger<SpapiOAuth>>()

            logger.LogInformation "Redirect received"

            // Setup Variables
            let q = Request.getQuery ctx
            let mutable sessionState = null

            // Handle getting all query params.
            // If any is missing or empty, throw an error.
            match
                q.TryGetStringNonEmpty "state",
                q.TryGetStringNonEmpty "spapi_oauth_code",
                q.TryGetStringNonEmpty "selling_partner_id"
            with
            | None, _, _ -> Response.ofHtml (Views.Error "Missing State.") ctx
            | _, None, _ -> Response.ofHtml (Views.Error "Missing Code.") ctx
            | _, _, None -> Response.ofHtml (Views.Error "Missing Selling Partner Id.") ctx
            | Some s, Some code, Some partnerId ->
                let givenState =
                    seq {
                        for char in s do
                            yield! System.BitConverter.GetBytes char
                    }

                // Validate the session and the state.
                match
                    ctx.Session.IsAvailable,
                    ctx.Session.TryGetValue(Constants.SPAPI_STATE_SESSION_KEY, &sessionState),
                    sessionState = (givenState |> Seq.toArray)
                with
                | false, _, _ -> Response.ofHtml (Views.Error "No Session") ctx
                | true, false, _ -> Response.ofHtml (Views.Error "No State") ctx
                | true, true, false -> Response.ofHtml (Views.Error "Invalid State") ctx
                | true, true, true ->
                    use client = clientFactory.CreateClient()

                    let content =
                        JsonContent.Create {|
                            grant_type = "authorization_code"
                            code = code
                            client_id = config.GetValue<string> "SPAPI_AUTH_CLIENT_ID"
                            client_secret = config.GetValue<string> "SPAPI_AUTH_CLIENT_SECRET"
                        |}

                    logger.LogInformation "Sending Amazon API Request to get refresh token"

                    // Use a Computational Expression for easier readability.
                    task {
                        use! response = client.PostAsync(Constants.AMAZON_API_TOKEN_URL, content)

                        if not response.IsSuccessStatusCode then
                            let! data = response.Content.ReadFromJsonAsync<AmazonSellerAPITokenErrorReponse>()
                            let! body = response.Content.ReadAsStringAsync()

                            return!
                                Response.ofHtml
                                    (Views.Error
                                     <| if data.error = "invalid_grant" then
                                            "Bad OAuth Token"
                                        else
                                            body)
                                    ctx

                        let! data = response.Content.ReadFromJsonAsync<AmazonSellerAPITokenResponse>()
                        return! Response.ofHtml (Views.Success data) ctx
                    }

module Program =

    let endpoints = [
        get "/" Handlers.AuthorizeGet
        post "/" Handlers.AuthorizePost
        get "/redirect" Handlers.RedirectGet
    ]

    let private ConfigureServices (services: IServiceCollection) =
        services
            .AddLogging()
            .AddDistributedMemoryCache()
            .AddSession(fun opts ->
                opts.IdleTimeout <- System.TimeSpan.FromSeconds 10.
                opts.Cookie.HttpOnly <- true
                opts.Cookie.IsEssential <- true)

    let private ConfigureWApp (wapp: WebApplication) =
        wapp.UseRouting().Use(fun (appl: IApplicationBuilder) -> appl.UseSession()).UseFalco(endpoints)

    let Build () =
        let builder = WebApplication.CreateBuilder()
        ignore <| ConfigureServices builder.Services

        let wapp = builder.Build()
        ConfigureWApp wapp



Program.Build().Run(Response.ofPlainText "Not Found")
