# frozen_string_literal: true

require "base64"
require "faraday"
require "jwt"
require "rack/auth/basic"
require_relative "fedcm"

module Lab
  class MockTransport < Faraday::Middleware
    PROVIDER_HOSTS = %w[accounts.google.com oauth2.googleapis.com www.googleapis.com].freeze

    def call(env)
      url = env.url
      if PROVIDER_HOSTS.include?(url.host)
        env.url = URI::HTTP.build(host: "127.0.0.1", port: PORT,
                                  path: "#{IDP_PATH}#{url.path}", query: url.query)
        env.request.proxy = nil
      end
      @app.call(env)
    end
  end

  class Grants
    CODE_TTL = 600
    TOKEN_TTL = 3600
    ISSUER = "https://accounts.google.com"

    attr_reader :jwks

    def initialize(signing_key)
      @signing_key = signing_key
      jwk = JWT::JWK.new(signing_key.public_key)
      @kid = jwk.kid
      @jwks = { keys: [jwk.export.merge(use: "sig", alg: "RS256")] }
      @codes = {}
      @access_tokens = {}
      @id_tokens = {}
      @mutex = Mutex.new
    end

    def authorize(account:, client_id:, redirect_uri:, scope:)
      @mutex.synchronize do
        now = Time.now.to_i
        @codes.delete_if { |_, grant| grant[:expires_at] <= now }
        code = SecureRandom.urlsafe_base64(32)
        @codes[code] = { account: account, client_id: client_id, redirect_uri: redirect_uri,
                         scope: scope, expires_at: now + CODE_TTL }
        code
      end
    end

    def exchange(code:, client_id:, redirect_uri:)
      @mutex.synchronize do
        now = Time.now.to_i
        @codes.delete_if { |_, grant| grant[:expires_at] <= now }
        grant = @codes[code]
        return [:invalid_grant, nil] unless grant && grant[:client_id] == client_id
        return [:redirect_uri_mismatch, nil] unless grant[:redirect_uri] == redirect_uri

        access_token = SecureRandom.urlsafe_base64(32)
        account = grant.fetch(:account)
        claims = {
          iss: ISSUER, aud: client_id, azp: client_id, sub: account.fetch("sub"),
          email: account.fetch("email"), email_verified: account.fetch("email_verified"),
          name: account.fetch("name"), iat: now, exp: now + TOKEN_TTL,
          at_hash: Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(access_token)[0, 16], padding: false)
        }
        id_token = JWT.encode(claims, @signing_key, "RS256", kid: @kid)
        record = { id_token: id_token, account: account, claims: claims, scope: grant.fetch(:scope) }
        prune_tokens(now)
        @access_tokens[access_token] = record
        @id_tokens[id_token] = record
        @codes.delete(code)

        [nil, { access_token: access_token, expires_in: TOKEN_TTL, scope: record.fetch(:scope),
                token_type: "Bearer", id_token: id_token }]
      end
    end

    def userinfo(access_token)
      find_token(@access_tokens, access_token)&.fetch(:account)
    end

    def assertion(account:, client_id:, nonce:, picture:)
      now = Time.now.to_i
      given_name = account.fetch("given_name")
      claims = {
        iss: ISSUER, azp: client_id, aud: client_id, sub: account.fetch("sub"), email: account.fetch("email"),
        email_verified: true, nbf: now, name: account.fetch("name"), picture: picture, given_name: given_name,
        family_name: account.fetch("family_name", account.fetch("name").delete_prefix(given_name).strip),
        iat: now, exp: now + TOKEN_TTL, jti: SecureRandom.uuid, nonce: nonce || SecureRandom.urlsafe_base64(32)
      }
      JWT.encode(claims, @signing_key, "RS256", kid: @kid, typ: "JWT")
    end

    def tokeninfo(access_token:, id_token:)
      record = id_token ? find_token(@id_tokens, id_token) : find_token(@access_tokens, access_token)
      return unless record

      record.fetch(:claims).merge(scope: record.fetch(:scope),
                                  expires_in: [record.fetch(:claims).fetch(:exp) - Time.now.to_i, 0].max.to_s)
    end

    private

    def find_token(index, token)
      @mutex.synchronize do
        prune_tokens(Time.now.to_i)
        index[token]
      end
    end

    def prune_tokens(now)
      @access_tokens.delete_if do |_, record|
        expired = record.fetch(:claims).fetch(:exp) <= now
        @id_tokens.delete(record.fetch(:id_token)) if expired
        expired
      end
    end
  end

  class MockIdentityProvider < WebApp
    set :brand, "Keystone ID"
    set :theme, "keystone"
    # FedCM routes validate request metadata and any required Origin directly.
    set :protection, allow_if: ->(env) { FedCM::REQUEST_PATHS.include?(env["PATH_INFO"]) }
    register FedCM

    AUTHORIZE_FIELDS = %w[client_id redirect_uri response_type scope state].freeze

    get "/o/oauth2/auth" do
      cache_control :no_store
      authorization_error("invalid_client") unless params["client_id"] == settings.data.client.fetch("client_id")
      authorization_error("redirect_uri_mismatch") unless params["redirect_uri"] == REDIRECT_URI
      redirect authorization_result(error: "unsupported_response_type") unless params["response_type"] == "code"

      if params.key?("account")
        account = settings.data.accounts[params["account"]]
        authorization_error("invalid_request") unless account

        scope = params["scope"]
        authorization_error("invalid_scope") unless scope.nil? || scope.is_a?(String)
        code = settings.grants.authorize(account: account, client_id: params["client_id"],
                                         redirect_uri: params["redirect_uri"], scope: scope || "email profile")
        remember_idp_account(account)
        redirect authorization_result(code: code)
      end

      scope = params["scope"]
      page :chooser, title: "Choose an account", error: nil, scopes: scope.is_a?(String) ? scope.split : [],
                     fields: params.slice(*AUTHORIZE_FIELDS), accounts: settings.data.accounts
    end

    post "/token" do
      cache_control :no_store
      headers "Pragma" => "no-cache"
      form = request.POST
      client_id, secret = client_credentials
      client = settings.data.client
      unless client_id == client.fetch("client_id") && secret.is_a?(String) &&
             Rack::Utils.secure_compare(secret, client.fetch("client_secret"))
        headers "WWW-Authenticate" => 'Basic realm="lab"' if env["HTTP_AUTHORIZATION"]
        halt 401, json(error: "invalid_client")
      end
      halt 400, json(error: "unsupported_grant_type") unless form["grant_type"] == "authorization_code"

      error, response = settings.grants.exchange(code: form["code"], client_id: client_id,
                                                 redirect_uri: form["redirect_uri"])
      halt 400, json(error: error.to_s) if error

      account = settings.grants.userinfo(response.fetch(:access_token))
      settings.data.set_approval(account.fetch("sub"), client_id, approved: true)
      json(response)
    end

    get "/oauth2/v3/userinfo" do
      cache_control :no_store
      token = env["HTTP_AUTHORIZATION"].to_s[/\ABearer ([^\s]+)\z/i, 1]
      account = settings.grants.userinfo(token)
      unless account
        headers "WWW-Authenticate" => 'Bearer error="invalid_token"'
        halt 401, json(error: "invalid_token")
      end

      json(account)
    end

    %i[get post].each do |method|
      public_send(method, "/oauth2/v3/tokeninfo") do
        cache_control :no_store
        info = settings.grants.tokeninfo(access_token: params["access_token"], id_token: params["id_token"])
        halt 400, json(error: "invalid_token") unless info

        json(info)
      end
    end

    get "/oauth2/v3/certs" do
      json(settings.grants.jwks)
    end

    helpers do
      def authorization_error(code)
        if request.preferred_type("application/json", "text/html") == "text/html" &&
           request.accept.any? { |entry| entry.to_s == "text/html" && entry.priority.first.positive? }
          halt 400, page(:chooser, title: "Authorization error", error: code)
        end

        halt 400, json(error: code)
      end

      def json(data)
        content_type :json
        headers "X-Content-Type-Options" => "nosniff"
        JSON.generate(data)
      end

      def authorization_result(**result)
        result[:state] = params["state"] if params.key?("state")
        "#{REDIRECT_URI}?#{Rack::Utils.build_query(result)}"
      end

      def client_credentials
        authorization = Rack::Auth::Basic::Request.new(env)
        return request.POST.values_at("client_id", "client_secret") unless authorization.provided?

        authorization.credentials if authorization.params && authorization.basic?
      end
    end
  end
end
