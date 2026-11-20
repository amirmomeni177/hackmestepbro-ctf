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
  AUTHORIZE_PATH = "#{IDP_PATH}/o/oauth2/auth"
  AUTH_PREFIX = "#{BASE}/users/auth"
  STRATEGY = "google_oauth2"
  REQUEST_PATH = "#{AUTH_PREFIX}/#{STRATEGY}"
  CALLBACK_PATH = "#{REQUEST_PATH}/callback"
  ASSETS_PATH = "#{BASE}/assets"
  PUBLIC_DIR = File.join(__dir__, "public")
  CSS_VERSION = Digest::SHA256.file(File.join(PUBLIC_DIR, "assets", "lab.css")).hexdigest[0, 12].freeze
  PORT = Integer(ENV.fetch("PORT", "18320"))
  public_origin = ENV["PUBLIC_ORIGIN"].to_s
  public_origin = "https://ctf.hackmestepbro.com" if public_origin.empty?
  PUBLIC_ORIGIN = public_origin.delete_suffix("/")
  REDIRECT_URI = "#{PUBLIC_ORIGIN}#{CALLBACK_PATH}"

  def self.failure_location(message)
    "#{HOME_PATH}?#{Rack::Utils.build_query(error: message, strategy: STRATEGY)}"
  end

  class Data
    attr_reader :secret, :client, :accounts, :signing_key

    def initialize(directory)
      @directory = directory
      @users_path = File.join(directory, "users.json")
      FileUtils.mkdir_p(directory, mode: 0o700)

      with_lock do
        @secret = load_or_create("secret") { SecureRandom.hex(64) }.strip
        client_json = load_or_create("client.json") do
          JSON.generate(client_id: "lab-#{SecureRandom.hex(16)}", client_secret: SecureRandom.hex(32))
        end
        @client = JSON.parse(client_json)
        @accounts = JSON.parse(load_or_create("idp-accounts.json") { JSON.generate(seed_accounts) })
        key_pem = load_or_create("idp-key.pem") { OpenSSL::PKey::RSA.generate(2048).to_pem }
        @signing_key = OpenSSL::PKey::RSA.new(key_pem)
        load_or_create("users.json") { "{}" }
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

    private

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
    use GraphQLAPI::AuthenticityToken

    before { cache_control :no_store }

    get "/" do
      user = settings.data.user(session["user_id"])
      if user
        workspace_page(user, title: "Home", section: :dashboard, error: params["error"])
      else
        page :home, title: "Creative workspace", error: params["error"]
      end
    end

    get "/signin" do
      page :signin, title: "Sign in", error: params["error"]
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
      headers "Allow" => "POST"
      graphql_request_error(405, "Use POST for GraphQL requests.")
    end

    get "#{GraphQLAPI::PATH}/schema" do
      content_type :txt
      GraphQLAPI::SDL
    end

    post GraphQLAPI::PATH do
      content_type :json
      limit = GraphQLAPI::MAX_BODY_BYTES
      graphql_request_error(413, "GraphQL requests cannot exceed 16 KB.") if request.content_length.to_i > limit

      raw = request.body.read(limit + 1).to_s.force_encoding(Encoding::UTF_8)
      graphql_request_error(413, "GraphQL requests cannot exceed 16 KB.") if raw.bytesize > limit
      graphql_request_error(415, "Use application/json for GraphQL requests.") unless request.media_type == "application/json"
      graphql_request_error(400, "Invalid JSON request.") unless raw.valid_encoding?
      payload = JSON.parse(raw)
      query, variables, operation = payload.values_at("query", "variables", "operationName") if payload.is_a?(Hash)
      unless query.is_a?(String) && (variables.nil? || variables.is_a?(Hash)) && (operation.nil? || operation.is_a?(String))
        graphql_request_error(400, "Expected a query string, an optional variables object, and an optional operationName string.")
      end

      user_id = session["user_id"]
      user = settings.data.user(user_id)
      result = GraphQLAPI::Schema.execute(query, variables: variables || {}, operation_name: operation, context: {
        user: user && WorkspaceData.new(user),
        csrf_valid: -> { GraphQLAPI::TOKEN_VALIDATOR.valid_header?(env) },
        update_name: ->(name) { settings.data.update_user_name(user_id, name) },
        sign_out: -> { reset_session }
      })
      JSON.generate(result.to_h)
    rescue JSON::ParserError
      graphql_request_error(400, "Invalid JSON request.")
    end

    post "/signout" do
      reset_session
      redirect HOME_PATH
    end

    helpers do
      def workspace_page(user, **locals)
        csrf_token = Rack::Protection::AuthenticityToken.token(session, path: "#{BASE}#{GraphQLAPI::PATH}")
        page :workspace, **locals, user: WorkspaceData.new(user), csrf_token: csrf_token
      end

      def graphql_request_error(status, message)
        content_type :json
        halt status, JSON.generate(errors: [{ message: message }])
      end

      def display_date(value)
        Time.iso8601(value).strftime("%b %-d, %Y")
      end

      def action_form(path, label, style:)
        token = Rack::Protection::AuthenticityToken.token(session, path: path)
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
