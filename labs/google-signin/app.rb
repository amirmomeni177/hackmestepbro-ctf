# frozen_string_literal: true

require "fileutils"
require "json"
require "openssl"
require "securerandom"
require "sinatra/base"
require "tempfile"
require "uri"

module Lab
  BASE = "/labs/google-signin"
  HOME_PATH = "#{BASE}/"
  IDP_PATH = "#{BASE}/idp"
  AUTH_PREFIX = "#{BASE}/users/auth"
  STRATEGY = "google_oauth2"
  REQUEST_PATH = "#{AUTH_PREFIX}/#{STRATEGY}"
  CALLBACK_PATH = "#{REQUEST_PATH}/callback"
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
      return unless id

      read_users.values.find { |user| user["id"] == id }
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
    disable :static
    set :host_authorization, permitted_hosts: [URI.parse(PUBLIC_ORIGIN).host, "127.0.0.1"]

    helpers do
      def escape(value)
        Rack::Utils.escape_html(value.to_s)
      end

      def page(title, content)
        <<~HTML
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>#{escape(title)}</title>
            <style>
              body { margin: 0; background: #f3f6f5; color: #182724; font: 1rem/1.5 system-ui, sans-serif; }
              main { max-width: 28rem; margin: 12vh auto 0; padding: 2rem; background: white;
                     border: 1px solid #d9e3e0; border-radius: 12px; }
              h1 { margin: 0; font-size: 1.75rem; }
              form { margin-top: 1.125rem; }
              button { padding: .65rem 1rem; border: 1px solid #245e51; border-radius: 6px;
                       background: #245e51; color: white; font: inherit; cursor: pointer; }
              button:hover { background: #184337; }
              button:focus-visible { outline: 2px solid #184337; outline-offset: 3px; }
              form.accounts { display: grid; gap: .65rem; }
              [role="alert"] { color: #9a2828; }
              @media (max-width: 36rem) { main { margin: 2rem 1rem; padding: 1.5rem; } }
            </style>
          </head>
          <body><main><h1>#{escape(title)}</h1>#{content}</main></body>
          </html>
        HTML
      end
    end
  end

  class RelyingParty < WebApp
    use Rack::Protection::AuthenticityToken

    before { cache_control :no_store }

    get "/" do
      user = settings.data.user(session["user_id"])
      status_text = if user
                      "Signed in as <strong>#{escape(user.fetch("name"))}</strong> (#{escape(user.fetch("email"))})."
                    else
                      "Signed out."
                    end
      error = params["error"]
      error_message = "<p role=\"alert\">Sign-in failed (#{escape(error)}).</p>" if error

      page("Sign-in lab", <<~HTML)
        <p>#{status_text}</p>
        #{error_message}
        #{action_form(REQUEST_PATH, "Sign in with Google")}
        #{action_form("#{BASE}/signout", "Sign out") if user}
      HTML
    end

    get "/users/auth/google_oauth2" do
      headers "Allow" => "POST"
      halt 405, "Method Not Allowed"
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

    post "/signout" do
      reset_session
      redirect HOME_PATH
    end

    helpers do
      def action_form(path, label)
        token = Rack::Protection::AuthenticityToken.token(session, path: path)
        <<~HTML
          <form method="post" action="#{escape(path)}">
            <input type="hidden" name="authenticity_token" value="#{escape(token)}">
            <button type="submit">#{escape(label)}</button>
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
