# frozen_string_literal: true

require "rack/session/cookie"
require "rack/static"
require "omniauth-google-oauth2"
require_relative "app"
require_relative "idp"

data = Lab::Data.new(ENV.fetch("LAB_DATA_DIR", File.join(__dir__, "data")))
Lab::RelyingParty.set :data, data
Lab::MockIdentityProvider.set :data, data
Lab::MockIdentityProvider.set :grants, Lab::Grants.new(data.signing_key)

OmniAuth.config.path_prefix = Lab::AUTH_PREFIX
OmniAuth.config.full_host = Lab::PUBLIC_ORIGIN
OmniAuth.config.on_failure = lambda do |env|
  [302, { "location" => Lab.failure_location(env.fetch("omniauth.error.type")),
          "cache-control" => "no-store" }, []]
end

# OmniAuth uses full request paths, so it runs before URLMap sets SCRIPT_NAME.
use Rack::Session::Cookie, key: "lab.session", secret: data.secret, path: Lab::BASE,
                         secure: true, httponly: true, same_site: :lax

use OmniAuth::Builder do
  provider :google_oauth2, data.client.fetch("client_id"), data.client.fetch("client_secret"),
           prompt: "select_account", skip_jwt: false,
           client_options: {
             authorize_url: "#{Lab::PUBLIC_ORIGIN}#{Lab::AUTHORIZE_PATH}",
             connection_build: lambda do |connection|
               builder = connection.builder
               builder.insert(0, Lab::MockTransport)
               builder.request :url_encoded
               builder.adapter :net_http
             end
           }
end

map Lab::BASE do
  use Rack::Static, urls: ["/assets"], root: Lab::PUBLIC_DIR, cascade: true,
                    cache_control: "public, max-age=86400"
  run Lab::RelyingParty
end

map Lab::IDP_PATH do
  run Lab::MockIdentityProvider
end
