# frozen_string_literal: true

module Lab
  module FedCM
    PREFIX = "/gsi/fedcm"
    COOKIE = "keystone.accounts"
    CONFIG = "/gsi/fedcm.json"
    ACCOUNT_LABEL = "n"
    ACCOUNTS = "#{PREFIX}/listaccounts"
    ASSERTION = "#{PREFIX}/issue"
    METADATA = "#{PREFIX}/clientmetadata"
    LOGIN = "#{PREFIX}/signin"
    METRICS = "#{PREFIX}/metrics"
    REVOKE = "#{PREFIX}/revoke"
    FALLBACK_ACCOUNTS = "/gsi/fallback/listaccounts"
    FALLBACK_ASSERTION = "/gsi/fallback/issue"
    REQUEST_PATHS = [CONFIG, ACCOUNTS, METADATA, ASSERTION, REVOKE, METRICS, FALLBACK_ACCOUNTS, FALLBACK_ASSERTION,
                     "/gsi/status", "/.well-known/web-identity"].freeze
    FORM_VALIDATOR = Rack::Protection::AuthenticityToken.new(nil)

    def self.url(path)
      "#{PUBLIC_ORIGIN}#{IDP_PATH}#{path}"
    end

    def self.registered(app)
      app.helpers Helpers

      ["/signin", LOGIN].each do |path|
        app.get(path) do
          cache_control :no_store
          page :idp_signin, title: "Sign in", accounts: settings.data.accounts,
                            signed_in: signed_in_accounts,
                            signin_token: local_action_token(IDP_SIGNIN_PATH),
                            signout_token: local_action_token("#{IDP_PATH}/signout")
        end
      end

      app.post "/signin" do
        cache_control :no_store
        require_idp_form_token
        account = settings.data.accounts[params["account"]]
        halt 400, json(error: "invalid_account") unless account

        remember_idp_account(account)
        # FedCM observes the login header in its popup. The normal page returns
        # to Lumora so its consent check can start One Tap again.
        redirect HOME_PATH, 303
      end

      app.post "/signout" do
        cache_control :no_store
        require_idp_form_token
        response.delete_cookie(COOKIE, idp_cookie_options)
        headers "Set-Login" => "logged-out"
        redirect IDP_SIGNIN_PATH, 303
      end

      app.get CONFIG do
        json(
          idtoken_endpoint: FedCM.url(ASSERTION),
          id_token_endpoint: FedCM.url(ASSERTION),
          id_assertion_endpoint: FedCM.url(ASSERTION),
          metrics_endpoint: FedCM.url(METRICS),
          accounts_endpoint: FedCM.url(ACCOUNTS),
          client_metadata_endpoint: FedCM.url(METADATA),
          client_id_metadata_endpoint: FedCM.url(METADATA),
          signin_url: FedCM.url(LOGIN),
          login_url: FedCM.url(LOGIN),
          revocation_endpoint: FedCM.url(REVOKE),
          disconnect_endpoint: FedCM.url(REVOKE),
          supports_add_account: true,
          supports_use_other_account: true,
          accounts: { include: ACCOUNT_LABEL },
          account_label: ACCOUNT_LABEL,
          modes: {
            button: { supports_use_other_account: true }, widget: { supports_use_other_account: false },
            active: { supports_use_other_account: true }, passive: { supports_use_other_account: false }
          },
          branding: {
            background_color: "#15544d", color: "#fffdfa",
            icons: [32, 40].map { |size| { url: FedCM.url("/gsi-static/keystone.svg"), size: size } }
          }
        )
      end

      app.get "/.well-known/web-identity" do
        json(provider_urls: [FedCM.url(CONFIG)], accounts_endpoint: FedCM.url(ACCOUNTS), login_url: FedCM.url(LOGIN))
      end

      app.get ACCOUNTS do
        cache_control :no_store
        require_webidentity
        json(accounts: fedcm_accounts)
      end

      app.get METADATA do
        cache_control :no_store
        fedcm_error("invalid_client") unless registered_client?(params["client_id"])
        json(privacy_policy_url: "#{PUBLIC_ORIGIN}#{BASE}/privacy",
             terms_of_service_url: "#{PUBLIC_ORIGIN}#{BASE}/terms")
      end

      app.post ASSERTION do
        cache_control :no_store
        require_webidentity
        issue_assertion
      end

      app.post METRICS do
        require_webidentity
        status 204
      end

      app.post REVOKE do
        cache_control :no_store
        require_webidentity
        form = request.POST
        require_client_origin(form["client_id"])
        account = signed_in_accounts.find { |entry| entry.values_at("sub", "email").include?(form["account_hint"]) }
        fedcm_error("invalid_request") unless account

        subject = account.fetch("sub")
        settings.data.set_approval(subject, form["client_id"], approved: false)
        json(account_id: subject)
      end

      app.get "/gsi/status" do
        cache_control :no_store
        headers "Vary" => "Origin"
        fedcm_error("invalid_client") unless registered_client?(params["client_id"])
        if env["HTTP_ORIGIN"]
          require_client_origin(params["client_id"])
        end
        json(signed_in: !signed_in_accounts.empty?)
      end

      app.get "/gsi/client" do
        content_type "application/javascript"
        File.read(File.join(PUBLIC_DIR, "keystone-client.js"))
      end

      app.get "/gsi-static/keystone.svg" do
        content_type "image/svg+xml"
        File.read(File.join(PUBLIC_DIR, "assets", "keystone.svg"))
      end

      app.get "/gsi-static/avatar/:subject.svg" do
        account = settings.data.accounts.values.find { |entry| entry["sub"] == params["subject"] }
        halt 404 unless account

        content_type "image/svg+xml"
        cache_control :public, max_age: 86_400
        <<~SVG
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
            <circle cx="32" cy="32" r="32" fill="#15544d"/>
            <text x="32" y="33" text-anchor="middle" dominant-baseline="central" fill="#fffdfa"
                  font-family="sans-serif" font-size="28">#{escape(initials(account.fetch("name")))}</text>
          </svg>
        SVG
      end

      app.get FALLBACK_ACCOUNTS do
        cache_control :no_store
        require_same_origin_client
        json(accounts: fedcm_accounts)
      end

      app.post FALLBACK_ASSERTION do
        cache_control :no_store
        require_same_origin_client
        issue_assertion
      end
    end

    module Helpers
      def idp_cookie_options
        { path: IDP_PATH, secure: true, httponly: true, same_site: :none }
      end

      def account_cookie_signature(subjects)
        OpenSSL::HMAC.hexdigest("SHA256", settings.data.secret, "#{COOKIE}:#{subjects}")
      end

      def signed_in_accounts
        subjects, signature = request.cookies[COOKIE].to_s.split("--", 2)
        return [] unless signature && Rack::Utils.secure_compare(signature, account_cookie_signature(subjects))

        accounts = settings.data.accounts.values.to_h { |account| [account.fetch("sub"), account] }
        subjects.split(",").filter_map { |subject| accounts[subject] }
      end

      def remember_idp_account(account)
        subjects = (signed_in_accounts.map { |entry| entry.fetch("sub") } | [account.fetch("sub")]).join(",")
        response.set_cookie(COOKIE, idp_cookie_options.merge(value: "#{subjects}--#{account_cookie_signature(subjects)}"))
        headers "Set-Login" => "logged-in"
      end

      def require_idp_form_token
        halt 403 unless FORM_VALIDATOR.accepts?(env)
      end

      def registered_client?(client_id)
        client_id == settings.data.client.fetch("client_id")
      end

      def require_client_origin(client_id)
        headers "Vary" => "Origin"
        fedcm_error("invalid_client") unless registered_client?(client_id)
        origin = settings.data.client.fetch("origin")
        fedcm_error("unauthorized_client", 403) unless env["HTTP_ORIGIN"] == origin

        headers "Access-Control-Allow-Origin" => origin, "Access-Control-Allow-Credentials" => "true"
      end

      def require_webidentity
        fedcm_error("invalid_request") unless env["HTTP_SEC_FETCH_DEST"] == "webidentity"
      end

      def require_same_origin_client
        # The custom header requires a preflight cross-origin. These routes
        # only accept same-origin browser fetches and do not allow preflights.
        unless env["HTTP_SEC_FETCH_SITE"] == "same-origin" && env["HTTP_X_KEYSTONE_ONE_TAP"] == "1"
          fedcm_error("invalid_request", 403)
        end
      end

      def fedcm_error(code, status = 400)
        halt status, json(error: { code: code, url: FedCM.url("/signin") })
      end

      def avatar_url(account)
        FedCM.url("/gsi-static/avatar/#{account.fetch('sub')}.svg")
      end

      def fedcm_accounts
        approvals = settings.data.approved_clients
        signed_in_accounts.map do |account|
          subject = account.fetch("sub")
          {
            id: subject, email: account.fetch("email"), name: account.fetch("name"),
            given_name: account.fetch("given_name"), picture: avatar_url(account),
            login_hints: account.values_at("email", "sub"), approved_clients: approvals.fetch(subject, []),
            label_hints: [ACCOUNT_LABEL]
          }
        end
      end

      def issue_assertion
        fedcm_error("invalid_request") unless request.media_type == "application/x-www-form-urlencoded"

        form = request.POST
        require_client_origin(form["client_id"])
        account = signed_in_accounts.find { |entry| entry["sub"] == form["account_id"] }
        fedcm_error("invalid_request") unless account

        nonce = form["nonce"]
        fedcm_error("invalid_request") unless nonce.nil? || nonce.is_a?(String)
        token = settings.grants.assertion(account: account, client_id: form["client_id"],
                                         nonce: nonce, picture: avatar_url(account))
        settings.data.set_approval(account.fetch("sub"), form["client_id"], approved: true)
        json(token: token)
      end
    end
  end
end
