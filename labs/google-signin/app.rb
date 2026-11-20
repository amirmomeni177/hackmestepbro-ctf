# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "openssl"
require "securerandom"
require "sinatra/base"
require "tempfile"
require "uri"
require_relative "graphql_api"

module Lab
  BASE = "/labs/google-signin"
  HOME_PATH = "#{BASE}/"
  SIGNIN_PATH = "#{BASE}/signin"
  ACCOUNT_PATH = "#{BASE}/account"
  IDP_PATH = "#{BASE}/idp"
  IDP_SIGNIN_PATH = "#{IDP_PATH}/signin"
  AUTHORIZE_PATH = "#{IDP_PATH}/o/oauth2/auth"
  AUTH_PREFIX = "#{BASE}/users/auth"
  STRATEGY = "google_oauth2"
  REQUEST_PATH = "#{AUTH_PREFIX}/#{STRATEGY}"
  CALLBACK_PATH = "#{REQUEST_PATH}/callback"
  ASSETS_PATH = "#{BASE}/assets"
  PUBLIC_DIR = File.join(__dir__, "public")
  CSS_VERSION = Digest::SHA256.file(File.join(PUBLIC_DIR, "assets", "lab.css")).hexdigest[0, 12].freeze
  WORKSPACE_JS_VERSION = Digest::SHA256.file(File.join(PUBLIC_DIR, "assets", "workspace.js")).hexdigest[0, 12].freeze
  PORT = Integer(ENV.fetch("PORT", "18320"))
  public_origin = ENV["PUBLIC_ORIGIN"].to_s
  public_origin = "https://ctf.hackmestepbro.com" if public_origin.empty?
  PUBLIC_ORIGIN = public_origin.delete_suffix("/")
  REDIRECT_URI = "#{PUBLIC_ORIGIN}#{CALLBACK_PATH}"

  def self.failure_location(message)
    "#{HOME_PATH}?#{Rack::Utils.build_query(error: message, strategy: STRATEGY)}"
  end

  class Data
    attr_reader :secret, :client, :accounts, :signing_key, :signing_certificate

    def initialize(directory)
      @directory = directory
      @users_path = File.join(directory, "users.json")
      @approvals_path = File.join(directory, "idp-approvals.json")
      FileUtils.mkdir_p(directory, mode: 0o700)

      with_lock do
        @secret = load_or_create("secret") { SecureRandom.hex(64) }.strip
        client_json = load_or_create("client.json") do
          JSON.generate(client_id: "lab-#{SecureRandom.hex(16)}", client_secret: SecureRandom.hex(32))
        end
        @client = JSON.parse(client_json).merge("origin" => PUBLIC_ORIGIN)
        @accounts = JSON.parse(load_or_create("idp-accounts.json") { JSON.generate(seed_accounts) })
        key_pem = load_or_create("idp-key.pem") { OpenSSL::PKey::RSA.generate(2048).to_pem }
        @signing_key = OpenSSL::PKey::RSA.new(key_pem)
        @signing_certificate = certificate_for(@signing_key)
        load_or_create("users.json") { "{}" }
        load_or_create("idp-approvals.json") { "{}" }
      end
    end

    def user(id)
      user_with_subject(id)&.last
    end

    def user_with_subject(id)
      return unless id

      read_users.find { |_, user| user["id"] == id }
    end

    def find_or_create_user(sub, email:, name:)
      with_lock do
        users = read_users
        users.fetch(sub) do
          user = { "id" => SecureRandom.uuid, "email" => email, "name" => name }
          users[sub] = user
          write(@users_path, JSON.generate(users))
          user
        end
      end
    end

    def update_user_name(id, name)
      with_lock do
        users = read_users
        user = users.values.find { |entry| entry["id"] == id }
        return unless user

        user["name"] = name
        write(@users_path, JSON.generate(users))
        user
      end
    end

    def approved_clients
      JSON.parse(File.read(@approvals_path))
    end

    def set_approval(subject, client_id, approved:)
      with_lock do
        approvals = approved_clients
        clients = approvals.fetch(subject, [])
        updated = approved ? clients | [client_id] : clients - [client_id]
        if updated != clients
          approvals[subject] = updated
          write(@approvals_path, JSON.generate(approvals))
        end
      end
    end

    private

    def certificate_for(key)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 1
      certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=Keystone ID")
      certificate.public_key = key.public_key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 86_400
      certificate.sign(key, OpenSSL::Digest::SHA256.new)
      certificate
    end

    def seed_accounts
      subjects = []
      subjects |= [SecureRandom.random_number(10**20...10**21).to_s] until subjects.size == 3

      %w[Alice Bob Carol].zip(subjects).to_h do |name, sub|
        email = "#{name.downcase}@lab.test"
        [email, { sub: sub, name: name, given_name: name, email: email, email_verified: true }]
      end
    end

    def read_users
      JSON.parse(File.read(@users_path))
    end

    def load_or_create(name)
      path = File.join(@directory, name)
      return File.read(path) if File.exist?(path)

      yield.tap { |contents| write(path, contents) }
    end

    def write(path, contents)
      Tempfile.create(File.basename(path), @directory) do |file|
        file.write(contents)
        file.flush
        file.fsync
        File.rename(file.path, path)
      end
    end

    def with_lock
      File.open(File.join(@directory, ".lock"), File::RDWR | File::CREAT, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        yield
      end
    end
  end

  class WebApp < Sinatra::Base
    set :absolute_redirects, false
    set :views, File.join(__dir__, "views")
    set :brand, "Lumora"
    set :theme, "lumora"
    disable :static
    set :host_authorization, permitted_hosts: [URI.parse(PUBLIC_ORIGIN).host, "127.0.0.1"]

    not_found { error_page("Page not found", "The requested page could not be found.") }
    error(Sinatra::BadRequest) { error_page("Bad request", "The lab could not read the request.") }
    error(500) { error_page("Internal server error", "The lab could not complete the request.") }

    helpers do
      def local_action_token(path)
        Rack::Protection::AuthenticityToken.token(session, path: path)
      end

      def escape(value)
        Rack::Utils.escape_html(value.to_s)
      end

      def page(view, title:, **locals)
        content_type :html
        erb view, locals: locals.merge(title: title)
      end

      def error_page(title, message)
        page :error, title: title, status_code: status, message: message
      end

      def initials(name)
        name_parts(name).first(2).map { |word| word[/\A\X/] }.join.upcase
      end

      def name_parts(name)
        name.to_s.split(/[[:space:]]+/).reject(&:empty?)
      end

      def icon(name)
        %(<svg class="icon" aria-hidden="true" focusable="false"><use href="#icon-#{escape(name)}"></use></svg>)
      end
    end
  end

  class RelyingParty < WebApp
    # GraphQL applies its own CSRF handling after identifying the operation.
    set :protection, allow_if: ->(env) { env["REQUEST_METHOD"] == "POST" && env["PATH_INFO"] == GraphQLAPI::PATH }
    use GraphQLAPI::AuthenticityToken

    before do
      cache_control :no_store
      @script_nonce = SecureRandom.base64(24)
      headers "Content-Security-Policy" => "script-src 'nonce-#{@script_nonce}'; object-src 'none'; base-uri 'none'"
    end

    get "/" do
      user = settings.data.user(session["user_id"])
      if user
        workspace_page(user, title: "Home", section: :dashboard, error: params["error"])
      else
        sign_in_page(:home, title: "Creative workspace", error: params["error"])
      end
    end

    get "/signin" do
      sign_in_page(:signin, title: "Sign in", error: params["error"])
    end

    get "/account" do
      subject, user = settings.data.user_with_subject(session["user_id"])
      redirect SIGNIN_PATH unless user

      workspace_page(user, title: "Account settings", section: :account, subject: subject)
    end

    get "/users/auth/google_oauth2" do
      headers "Allow" => "POST"
      status 405
      error_page("Method not allowed", "Start sign-in from the lab to submit a POST request.")
    end

    get "/users/auth/google_oauth2/callback" do
      auth = env["omniauth.auth"]
      halt 404 unless auth

      user = settings.data.find_or_create_user(auth.uid, email: auth.info.email, name: auth.info.name)
      reset_session
      session["user_id"] = user.fetch("id")
      redirect HOME_PATH
    end

    get "/users/auth/failure" do
      redirect Lab.failure_location(params["message"])
    end

    get "/me" do
      content_type :json
      user = settings.data.user(session["user_id"])
      JSON.generate(signed_in: !user.nil?, user: user)
    end

    get GraphQLAPI::PATH do
      if request.GET.empty?
        headers "Allow" => "POST"
        graphql_request_error(405, "Use POST for GraphQL requests.")
      end
      execute_graphql(request.GET, form: true)
    end

    get "#{GraphQLAPI::PATH}/schema" do
      content_type :txt
      GraphQLAPI::SDL
    end

    get "/persisted.json" do
      content_type :json
      GraphQLAPI::MANIFEST
    end

    %w[privacy terms].each do |document|
      get "/#{document}" do
        page :policy, title: document == "privacy" ? "Privacy policy" : "Terms of service", document: document
      end
    end

    post GraphQLAPI::PATH do
      content_type :json
      limit = GraphQLAPI::MAX_BODY_BYTES
      graphql_request_error(413, "GraphQL requests cannot exceed 16 KB.") if request.content_length.to_i > limit

      request.body.rewind
      raw = request.body.read(limit + 1) || +""
      raw.force_encoding(Encoding::UTF_8)
      graphql_request_error(413, "GraphQL requests cannot exceed 16 KB.") if raw.bytesize > limit
      case request.media_type
      when "application/json"
        graphql_request_error(400, "Invalid JSON request.") unless raw.valid_encoding?
        execute_graphql(JSON.parse(raw))
      when "application/x-www-form-urlencoded"
        execute_graphql(Rack::Utils.parse_nested_query(raw), form: true)
      else
        execute_graphql({})
      end
    rescue JSON::ParserError
      graphql_request_error(400, "Invalid JSON request.")
    rescue Rack::QueryParser::ParameterTypeError, Rack::QueryParser::InvalidParameterError, Rack::QueryParser::QueryLimitError
      graphql_request_error(400, "Invalid form request.")
    end

    post "/signout" do
      reset_session
      redirect HOME_PATH
    end

    helpers do
      def workspace_page(user, **locals)
        page :workspace, **locals, user: WorkspaceData.new(user), csrf_token: expose_csrf_token, app_script: true
      end

      def sign_in_page(view, **locals)
        one_tap = !settings.data.user(session["user_id"]) && request.path_info != "/account"
        page view, **locals, csrf_token: expose_csrf_token, app_script: one_tap, one_tap: one_tap
      end

      def expose_csrf_token
        token = local_action_token("#{BASE}#{GraphQLAPI::PATH}")
        response.set_cookie("csrftoken", value: token, path: BASE, secure: true, same_site: :lax)
        token
      end

      def execute_graphql(payload, form: false)
        graphql_request_error(400, "Expected a GraphQL request object.") unless payload.is_a?(Hash)
        source, variables, operation, extensions = payload.values_at("query", "variables", "operationName", "extensions")
        missing_query = source.nil? || (source.is_a?(String) && source.strip.empty?)
        if missing_query && extensions.is_a?(Hash)
          source = GraphQLAPI::PERSISTED_QUERIES[extensions["operationId"]]
        elsif missing_query
          source = nil
        end
        graphql_request_error(200, "No query string was present") if source.nil?
        variables = variables.empty? ? nil : JSON.parse(variables) if form && variables.is_a?(String)
        unless source.is_a?(String) && (variables.nil? || variables.is_a?(Hash)) && (operation.nil? || operation.is_a?(String))
          graphql_request_error(400, "Expected a query string, an optional variables object, and an optional operationName string.")
        end

        query = GraphQL::Query.new(GraphQLAPI::Schema, source, variables: variables || {}, operation_name: operation)
        if query.mutation? && !request.post?
          status 403
          return error_page("Forbidden", "Use POST for GraphQL mutations.")
        end

        null_session = query.mutation? && !GraphQLAPI::HEADER_VALIDATOR.accepts?(env)
        active_session = null_session ? {} : session
        env.fetch("rack.session.options")[:skip] = true if null_session
        user = settings.data.user(active_session["user_id"])
        query.context[:user] = user && WorkspaceData.new(user)
        query.context[:update_name] = ->(name) { settings.data.update_user_name(active_session["user_id"], name) }
        clear_session = -> { null_session ? active_session.clear : reset_session }
        query.context[:sign_out] = clear_session
        query.context[:oauth_sign_in] = lambda do |token|
          claims = settings.id_token_validator.check(token, settings.data.client.fetch("client_id"))
          user = settings.data.find_or_create_user(claims.fetch("sub"), email: claims.fetch("email"), name: claims.fetch("name"))
          clear_session.call
          active_session["user_id"] = user.fetch("id")
          user
        end
        content_type :json
        JSON.generate(query.result.to_h)
      rescue JSON::ParserError
        graphql_request_error(400, "Invalid JSON request.")
      end

      def graphql_request_error(status, message)
        content_type :json
        halt status, JSON.generate(errors: [{ message: message }])
      end

      def display_date(value)
        Time.iso8601(value).strftime("%b %-d, %Y")
      end

      def action_form(path, label, style:)
        token = local_action_token(path)
        <<~HTML
          <form method="post" action="#{escape(path)}">
            <input type="hidden" name="authenticity_token" value="#{escape(token)}">
            <button class="button #{escape(style)}" type="submit">#{escape(label)}</button>
          </form>
        HTML
      end

      def reset_session
        session.clear
        env.fetch("rack.session.options")[:renew] = true
      end
    end
  end
end
